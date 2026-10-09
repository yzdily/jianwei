"""ast_behavior 分析器 —— Python AST 行为分析。

检测脚本里的危险调用（设计 §3.2）：
  命令执行 / 动态执行 / 破坏性删除 / 不安全反序列化 / 文件写 / 网络 / 动态导入 / 硬编码密钥
映射 → LLM06 过度代理 / LLM03 供应链 / LLM02 敏感泄露。
绝不执行被扫代码，仅 AST 静态解析。

匹配策略（2026-10-09 修复 P1 漏报）：
  - 调用名取**点分全名**（`os.system` / `subprocess.run` / `shutil.rmtree` / `pickle.loads`），
    不再只取属性短名——修复「字典键写 subprocess、实际取到 run，规则永不命中」的死代码问题。
  - 同时保留裸名匹配（`from os import system; system(...)` 这类别名调用）。
  - `open(path, "w"|"a"|"x"|"+")` 单独判定为文件写（读模式不报，避免误报）。
"""
from __future__ import annotations

import ast

from core.log import get_logger
from .base import Analyzer, FileEntry, ScanContext, SkillFinding, Severity, is_text_file

log = get_logger("skill_scan.ast_behavior")

# 危险调用（**点分全名** 或 裸名）→ (owasp, severity, recommendation)
DANGEROUS_CALLS: dict[str, tuple[str, "Severity", str]] = {
    # ---- 命令执行（LLM06 过度代理）----
    "os.system": ("LLM06", Severity.HIGH, "检测到 os.system 调用，属命令执行高危面，建议移除或严格沙箱化。"),
    "os.popen": ("LLM06", Severity.HIGH, "检测到 os.popen 调用，存在命令执行风险，建议移除。"),
    "subprocess.run": ("LLM06", Severity.HIGH, "检测到 subprocess.run 命令执行，建议最小权限 + 命令白名单，禁用 shell=True。"),
    "subprocess.call": ("LLM06", Severity.HIGH, "检测到 subprocess.call 命令执行，建议最小权限 + 命令白名单，禁用 shell=True。"),
    "subprocess.Popen": ("LLM06", Severity.HIGH, "检测到 subprocess.Popen 命令执行，建议审查调用参数来源并沙箱化。"),
    "subprocess.check_output": ("LLM06", Severity.HIGH, "检测到 subprocess.check_output 命令执行，建议最小权限 + 白名单。"),
    "subprocess.check_call": ("LLM06", Severity.HIGH, "检测到 subprocess.check_call 命令执行，建议最小权限 + 白名单。"),
    "subprocess.getoutput": ("LLM06", Severity.HIGH, "检测到 subprocess.getoutput 命令执行，建议移除。"),
    "subprocess.getstatusoutput": ("LLM06", Severity.HIGH, "检测到 subprocess.getstatusoutput 命令执行，建议移除。"),
    # 裸名（from os/subprocess import ... 的别名）
    "system": ("LLM06", Severity.HIGH, "检测到 system 调用（疑似 os.system 别名），属命令执行高危面。"),
    "popen": ("LLM06", Severity.HIGH, "检测到 popen 调用（疑似 os.popen 别名），存在命令执行风险。"),
    # ---- 动态执行 ----
    "eval": ("LLM06", Severity.HIGH, "检测到 eval 调用，可造成代码执行，建议移除。"),
    "exec": ("LLM06", Severity.HIGH, "检测到 exec 调用，可造成代码执行，建议移除。"),
    "compile": ("LLM06", Severity.MEDIUM, "检测到 compile 调用，可用于动态构造可执行字节码，建议审查来源。"),
    # ---- 破坏性删除 ----
    "shutil.rmtree": ("LLM06", Severity.HIGH, "检测到 shutil.rmtree 递归删除，可能造成不可逆数据破坏，建议移除或加二次确认。"),
    "os.remove": ("LLM06", Severity.MEDIUM, "检测到 os.remove 删除文件，建议审查删除目标范围。"),
    "os.unlink": ("LLM06", Severity.MEDIUM, "检测到 os.unlink 删除文件，建议审查删除目标范围。"),
    "os.rmdir": ("LLM06", Severity.MEDIUM, "检测到 os.rmdir 删除目录，建议审查删除目标范围。"),
    "os.removedirs": ("LLM06", Severity.MEDIUM, "检测到 os.removedirs 递归删除目录，建议审查删除目标范围。"),
    "rmtree": ("LLM06", Severity.HIGH, "检测到 rmtree 调用（疑似 shutil.rmtree 别名），可能造成不可逆数据破坏。"),
    # ---- 不安全反序列化（RCE）----
    "pickle.loads": ("LLM06", Severity.CRITICAL, "检测到 pickle.loads 反序列化，可导致任意代码执行（RCE），禁止加载不可信数据。"),
    "pickle.load": ("LLM06", Severity.CRITICAL, "检测到 pickle.load 反序列化，可导致任意代码执行（RCE），禁止加载不可信数据。"),
    "cPickle.loads": ("LLM06", Severity.CRITICAL, "检测到 cPickle.loads 反序列化，可导致任意代码执行（RCE），禁止加载不可信数据。"),
    "dill.loads": ("LLM06", Severity.CRITICAL, "检测到 dill.loads 反序列化，可导致任意代码执行（RCE），禁止加载不可信数据。"),
    "marshal.loads": ("LLM06", Severity.CRITICAL, "检测到 marshal.loads 反序列化，可导致代码执行，禁止加载不可信数据。"),
    "yaml.load": ("LLM06", Severity.HIGH, "检测到 yaml.load（非 safe_load），可被构造为任意对象/代码执行，建议改用 yaml.safe_load。"),
    # ---- 网络 / 动态导入 ----
    "socket.socket": ("LLM06", Severity.MEDIUM, "检测到 socket 网络调用，可能被用于 SSRF/C2，建议限制目标地址。"),
    "__import__": ("LLM03", Severity.MEDIUM, "检测到动态 __import__，可能被用于加载未授权模块。"),
    "importlib.import_module": ("LLM03", Severity.MEDIUM, "检测到 importlib.import_module 动态导入，建议固定模块白名单。"),
}

# 仅按「方法短名」匹配的危险调用（实例化对象上调用，点分全名不可预测）
DANGEROUS_METHODS: dict[str, tuple[str, "Severity", str]] = {
    "write_text": ("LLM06", Severity.MEDIUM, "检测到文件写入（write_text），可能篡改文件，建议审查目标路径。"),
    "write_bytes": ("LLM06", Severity.MEDIUM, "检测到文件写入（write_bytes），可能篡改文件，建议审查目标路径。"),
}

# open() 的写模式字符：命中任一即视为「写文件」
_WRITE_MODE_CHARS = ("w", "a", "x", "+")
_OPEN_NAMES = ("open", "io.open")

SECRET_ASSIGN_RE = None  # 在运行时编译


class ASTBehaviorAnalyzer(Analyzer):
    name = "ast_behavior"
    enabled_strategies = ("standard", "redteam", "compliance")

    def analyze(self, files: list[FileEntry], ctx: ScanContext) -> list[SkillFinding]:
        findings: list[SkillFinding] = []
        for entry in files:
            if not entry.rel_path.endswith(".py"):
                continue
            if not is_text_file(entry):
                continue
            content = entry.content or ""
            if not content:
                try:
                    with open(entry.abs_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except Exception:
                    continue
            try:
                tree = ast.parse(content, filename=entry.rel_path)
            except SyntaxError as e:
                # 语法错误本身也是风险信号（可能是混淆/恶意）
                findings.append(SkillFinding(
                    name="ast:syntax_error",
                    check_type="skill_ast_syntax",
                    severity=Severity.LOW,
                    file_path=entry.rel_path,
                    line=getattr(e, "lineno", 0) or 0,
                    description=f"Python 文件存在语法错误：{e.msg}",
                    recommendation="修复语法错误，语法异常可能意味着混淆或人为构造的载荷。",
                    confidence=0.6,
                ))
                continue
            findings.extend(self._walk(tree, entry))
        return findings

    def _walk(self, tree: ast.AST, entry: FileEntry) -> list[SkillFinding]:
        out: list[SkillFinding] = []
        for node in ast.walk(tree):
            # ---- 危险函数调用 ----
            if isinstance(node, ast.Call):
                full = self._func_name(node.func)
                leaf = full.rsplit(".", 1)[-1] if full else ""

                hit = DANGEROUS_CALLS.get(full)
                hit_name = full
                if hit is None and leaf in DANGEROUS_METHODS:
                    hit = DANGEROUS_METHODS[leaf]
                    hit_name = leaf
                if hit is not None:
                    owasp, sev, rec = hit
                    out.append(SkillFinding(
                        name=f"ast:call:{hit_name}",
                        check_type="skill_ast_dangerous_call",
                        severity=sev,
                        file_path=entry.rel_path,
                        line=node.lineno,
                        owasp=owasp,
                        description=f"{entry.rel_path}:{node.lineno} 调用危险函数 `{full or leaf}()`",
                        recommendation=rec,
                        confidence=0.8,
                        safe_to_install=False,
                    ))
                else:
                    wf = self._open_write_finding(node, full, entry)
                    if wf is not None:
                        out.append(wf)

            # ---- 硬编码密钥赋值：VAR = "长字符串" ----
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and isinstance(node.value, ast.Constant) \
                            and isinstance(node.value.value, str):
                        name = target.id.lower()
                        val = node.value.value
                        if ("key" in name or "secret" in name or "token" in name or "password" in name) \
                                and len(val) >= 16:
                            out.append(SkillFinding(
                                name="ast:hardcoded_secret",
                                check_type="skill_ast_secret",
                                severity=Severity.CRITICAL,
                                file_path=entry.rel_path,
                                line=node.lineno,
                                owasp="LLM02",
                                description=f"{entry.rel_path}:{node.lineno} 变量 `{target.id}` 硬编码疑似密钥（长度 {len(val)}）",
                                recommendation="将密钥迁移至环境变量 / 密钥管理服务，切勿入库。",
                                confidence=0.85,
                                safe_to_install=False,
                                evidence=val[:8] + "****",
                            ))
        return out

    def _open_write_finding(self, node: ast.Call, full: str, entry: FileEntry) -> SkillFinding | None:
        """open(...) / io.open(...) 且模式为写时，报「文件写」。读模式不报（避免误报）。"""
        if full not in _OPEN_NAMES:
            return None
        mode: str | None = None
        if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str):
            mode = node.args[1].value
        for kw in node.keywords:
            if kw.arg == "mode" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                mode = kw.value.value
        if not mode or not any(ch in mode for ch in _WRITE_MODE_CHARS):
            return None
        return SkillFinding(
            name="ast:file_write",
            check_type="skill_ast_file_write",
            severity=Severity.HIGH,
            file_path=entry.rel_path,
            line=node.lineno,
            owasp="LLM06",
            description=f"{entry.rel_path}:{node.lineno} 以写模式打开文件（mode={mode!r}），可能篡改/覆盖系统文件",
            recommendation="限制可写路径白名单；对 /etc、/usr 等系统目录的写入应直接禁止。",
            confidence=0.8,
            safe_to_install=False,
            evidence=f"open(..., {mode!r})",
        )

    @staticmethod
    def _func_name(func: ast.AST) -> str:
        """返回**点分全名**：`os.system` / `subprocess.run` / `pickle.loads`；裸名返回 `eval`。

        无法向上解析到 Name 时，退化为已有的属性段（如 `f().system` → `system`）。
        """
        parts: list[str] = []
        node = func
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
        if not parts:
            return ""
        return ".".join(reversed(parts))

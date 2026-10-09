"""ast_behavior 分析器 —— Python AST 行为分析。

检测脚本里的危险调用（设计 §3.2）：
  subprocess / os.system / eval / exec / socket / 动态 import / 硬编码密钥
映射 → LLM06 过度代理 / LLM03 供应链。
绝不执行被扫代码，仅 AST 静态解析。
"""
from __future__ import annotations

import ast

from core.log import get_logger
from .base import Analyzer, FileEntry, ScanContext, SkillFinding, Severity, is_text_file

log = get_logger("skill_scan.ast_behavior")

# 危险调用名 → (owasp, severity, recommendation)
DANGEROUS_CALLS = {
    "system": ("LLM06", Severity.HIGH, "检测到 os.system 调用，属命令执行高危面，建议移除或严格沙箱化。"),
    "subprocess": ("LLM06", Severity.HIGH, "检测到 subprocess 调用，可能被用于命令执行，建议最小权限 + 白名单。"),
    "popen": ("LLM06", Severity.HIGH, "检测到 Popen 调用，存在命令执行风险，建议审查调用参数来源。"),
    "eval": ("LLM06", Severity.HIGH, "检测到 eval 调用，可造成代码执行，建议移除。"),
    "exec": ("LLM06", Severity.HIGH, "检测到 exec 调用，可造成代码执行，建议移除。"),
    "socket": ("LLM06", Severity.MEDIUM, "检测到 socket 网络调用，可能被用于 SSRF/C2，建议限制目标地址。"),
    "__import__": ("LLM03", Severity.MEDIUM, "检测到动态 __import__，可能被用于加载未授权模块。"),
    "import_module": ("LLM03", Severity.MEDIUM, "检测到 importlib.import_module 动态导入，建议固定模块白名单。"),
}

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
            # 危险函数调用
            if isinstance(node, ast.Call):
                func_name = self._func_name(node.func)
                if func_name in DANGEROUS_CALLS:
                    owasp, sev, rec = DANGEROUS_CALLS[func_name]
                    out.append(SkillFinding(
                        name=f"ast:call:{func_name}",
                        check_type="skill_ast_dangerous_call",
                        severity=sev,
                        file_path=entry.rel_path,
                        line=node.lineno,
                        owasp=owasp,
                        description=f"{entry.rel_path}:{node.lineno} 调用危险函数 `{func_name}()`",
                        recommendation=rec,
                        confidence=0.8,
                        safe_to_install=False,
                    ))
            # 硬编码密钥赋值：VAR = "长字符串"
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

    @staticmethod
    def _func_name(func: ast.AST) -> str:
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return func.attr
        return ""

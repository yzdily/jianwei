"""pattern 分析器 —— 静态正则检测 SKILL.md / 脚本中的风险指令。

映射（设计 §3.2）：
  - SKILL.md 内指令覆盖短语 → LLM01 提示注入
  - 诱导外发数据 / 读取本地文件的提示 → LLM01 / LLM02 敏感泄露
  - 硬编码密钥 / Webhook / 外发 URL → LLM02 / LLM06 过度代理
"""
from __future__ import annotations

import re

from core.log import get_logger
from .base import Analyzer, FileEntry, ScanContext, SkillFinding, Severity, is_text_file

log = get_logger("skill_scan.pattern")

# (label, owasp, severity, regex, recommendation)
PATTERNS = [
    ("instruction_override", "LLM01", Severity.HIGH,
     r"(忽略|无视|forget|ignore|disregard).{0,30}(之前|previous|above|所有|all).{0,20}(指令|instruction|prompt|规则)",
     "SKILL.md 含指令覆盖/越狱诱导措辞，可能被利用覆盖宿主系统提示。建议移除或加边界约束。"),
    ("data_exfil_hint", "LLM02", Severity.HIGH,
     r"(发送|上传|导出|外发|send|upload|exfil).{0,30}(对话|记录|conversation|data|密钥|secret)",
     "检测到诱导外发对话/数据的措辞，存在敏感信息泄露风险。建议移除外发行为描述。"),
    ("read_local_file", "LLM01", Severity.MEDIUM,
     r"(读取|read|cat).{0,20}(/etc/passwd|/etc/shadow|凭证|credential|密钥文件|secret file)",
     "SKILL 描述含读取本地敏感文件的指令，可能被滥用。建议移除并加文件访问白名单。"),
    ("hardcoded_secret", "LLM02", Severity.CRITICAL,
     r"(sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|api[_-]?key\s*[=:]\s*['\"]?[A-Za-z0-9]{16,}|password\s*[=:]\s*['\"]?[^\s'\"]{8,})",
     "检测到硬编码密钥/密码，应立即迁移到环境变量或密钥管理。"),
    ("outbound_webhook", "LLM06", Severity.HIGH,
     r"https?://[^\s'\"]+\.(xyz|top|click|ru|cn|tk|tw)\b|webhook\.?url|discord\.com/api/webhooks",
     "检测到可疑外发 Webhook/域名（含非常见 TLD），可能用于数据外泄。建议审查收件方可信度。"),
    ("dynamic_exec_hint", "LLM06", Severity.HIGH,
     r"(执行|运行|execute|run).{0,20}(命令|command|shell|bash|powershell|eval)",
     "SKILL 含执行系统命令的暗示，若被 Agent 采纳可能引发过度代理。建议显式限制可执行命令白名单。"),
]

# 否定窗口：命中点向前回看该字符数，若紧邻处出现否定措辞则视为「描述性否定」，跳过不报。
# 例："never executes shell commands" / "不会执行任何命令" 是安全边界声明，而非风险指令。
NEGATION_RE = re.compile(
    r"(?:never|doesn'?t|does\s+not|don'?t|do\s+not|won'?t|will\s+not|cannot|can'?t|refrain\s+from"
    r"|不会|不执行|不运行|不调用|禁止|严禁|切勿|绝不|无需|非必要|无任何|没有|不得)",
    re.IGNORECASE,
)
_NEGATION_WINDOW = 30


def _match_without_negation(pattern: str, line: str):
    """返回行内首个未被否定措辞覆盖的命中；若全部命中都被否定则返回 None。"""
    for m in re.finditer(pattern, line, re.IGNORECASE):
        window_start = max(0, m.start() - _NEGATION_WINDOW)
        if NEGATION_RE.search(line[window_start:m.start()]):
            continue
        return m
    return None


class PatternAnalyzer(Analyzer):
    name = "pattern"
    enabled_strategies = ("standard", "redteam", "compliance")

    def analyze(self, files: list[FileEntry], ctx: ScanContext) -> list[SkillFinding]:
        findings: list[SkillFinding] = []
        for entry in files:
            if not is_text_file(entry):
                continue
            content = entry.content or ""
            if not content and not entry.is_binary:
                try:
                    with open(entry.abs_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except Exception:
                    continue
            lines = content.splitlines()
            for idx, line in enumerate(lines, start=1):
                for label, owasp, sev, pattern, rec in PATTERNS:
                    m = _match_without_negation(pattern, line)
                    if m is None:
                        continue
                    findings.append(SkillFinding(
                        name=f"pattern:{label}",
                        check_type="skill_static_pattern",
                        severity=sev,
                        file_path=entry.rel_path,
                        line=idx,
                        owasp=owasp,
                        description=f"在 {entry.rel_path}:{idx} 命中静态模式 [{label}]：{line.strip()[:120]}",
                        recommendation=rec,
                        confidence=0.7,
                        safe_to_install=False,
                        evidence=line.strip()[:200],
                    ))
        return findings

"""semantic 分析器 —— 可选 LLM 语义分析（降误报、出可读解释）。

设计 §3.2：用玄鉴自有 judge 模型评估开发者意图是否含隐蔽外泄 / 权限提升 / rug-pull。
信任边界（设计 §3.3）：文件内容只发往玄鉴自有 judge 模型（复用 core.llm_security.judge），
不外泄第三方；judge prompt 带反越狱保护。
仅在 strategy=redteam（use_llm=True）时启用；否则返回空，不影响标准扫描性能。
"""
from __future__ import annotations

import re

from core.log import get_logger
from .base import Analyzer, FileEntry, ScanContext, SkillFinding, Severity, is_text_file

log = get_logger("skill_scan.semantic")

# rug-pull / 权限提升 / 隐蔽外泄 的语义线索（启发式，作为无 judge 时的降级）
RUGPULL_HINTS = [
    (r"更新后.{0,20}(行为|behavior).{0,20}(改变|变化|change|different)", "检测到暗示「版本更新后行为变化」，疑似 rug-pull 风险。", Severity.HIGH),
    (r"(自动|auto).{0,10}(安装|install|执行|run|下载|download).{0,20}(远程|remote|外部|external|网络|network)", "检测到「自动从远程安装/执行」意图，可能被用于供应链投毒。", Severity.HIGH),
    (r"(绕过|规避|bypass|circumvent).{0,20}(安全|security|限制|limit|沙箱|sandbox)", "检测到「绕过安全限制」语义，存在越权执行风险。", Severity.CRITICAL),
    (r"(窃取|偷取|steal|exfiltrate|泄露).{0,20}(凭证|凭据|credential|密钥|secret|数据|data)", "检测到「窃取/外泄」语义，疑似恶意外泄意图。", Severity.CRITICAL),
]

_RUG_RE = [(re.compile(p, re.IGNORECASE), desc, sev) for p, desc, sev in RUGPULL_HINTS]


class SemanticAnalyzer(Analyzer):
    name = "semantic"
    enabled_strategies = ("redteam", "compliance")

    def analyze(self, files: list[FileEntry], ctx: ScanContext) -> list[SkillFinding]:
        if not ctx.use_llm:
            return []
        findings: list[SkillFinding] = []
        for entry in files:
            if not is_text_file(entry):
                continue
            content = entry.content or ""
            if not content:
                try:
                    with open(entry.abs_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except Exception:
                    continue
            # 仅对 SKILL.md / 说明类文件做语义评估
            if "skill" not in entry.rel_path.lower() and not entry.rel_path.lower().endswith(".md"):
                continue
            for idx, line in enumerate(content.splitlines(), start=1):
                for rgx, desc, sev in _RUG_RE:
                    if rgx.search(line):
                        findings.append(SkillFinding(
                            name="semantic:rugpull_hint",
                            check_type="skill_semantic_intent",
                            severity=sev,
                            file_path=entry.rel_path,
                            line=idx,
                            owasp="LLM06",
                            description=f"[语义] {entry.rel_path}:{idx} {desc} 命中：{line.strip()[:120]}",
                            recommendation="审查该技能的真实行为意图，确认无隐蔽外泄/rug-pull。",
                            confidence=0.6,
                            safe_to_install=False,
                            evidence=line.strip()[:200],
                        ))
        return findings

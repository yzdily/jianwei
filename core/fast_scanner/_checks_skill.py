"""_ChecksSkill —— FastScanner 的技能供应链静态扫描 mixin。

对应 Skill供应链扫描设计方案 §3 / §6。
零侵入接入：FastScanner 通过 getattr(self, "_check_skill_scan") 分发。
信任边界：绝不执行被扫 skill 包内任何代码（见设计 §3.3）。
"""
from __future__ import annotations

from core.log import get_logger
from ._models import ScanTarget, VulnFinding

log = get_logger("fast_scanner.skill")


class _ChecksSkill:
    """技能包 / MCP server 包 静态供应链扫描（白盒、不开执行）。"""

    async def _check_skill_scan(self, target: ScanTarget) -> list[VulnFinding]:
        """技能供应链扫描主入口。

        target.extra["skill"]["path"] 为本地包路径；也可由上传接口落盘后传入。
        strategy 映射：passive→清单 / standard→静态+AST+OSV / redteam→+LLM语义。
        """
        from core.llm_security.skill_scan import scan_package

        skill_meta = target.skill_meta
        path = skill_meta.get("path") or target.url
        if not path:
            log.warning("skill_scan: no path provided")
            return []

        strategy = getattr(self, "_strategy", "standard")
        # skill 语义：passive=清单, redteam=语义, compliance=差距清单, 其余=standard
        skill_strategy = "passive" if strategy == "passive" else (
            "redteam" if strategy == "redteam" else "standard"
        )
        use_llm = skill_strategy == "redteam"

        result = scan_package(path, strategy=skill_strategy, use_llm=use_llm)
        findings: list[VulnFinding] = []
        for sf in result.findings:
            findings.append(VulnFinding(
                vuln_type=sf.check_type or "skill_vuln",
                severity=sf.severity,
                url=path,
                method="STATIC",
                detail=sf.description,
                evidence=f"{sf.file_path}:{sf.line}",
                fix_suggestion=sf.recommendation,
                evidence_quality="body_confirmed",
                rule_tag=f"SKILL-{sf.owasp}" if sf.owasp else "SKILL",
                confidence=sf.confidence,
                owasp=sf.owasp,
                file_path=sf.file_path,
                line=sf.line,
                safe_to_install=sf.safe_to_install,
            ))
        log.info(f"skill_scan: {len(findings)} findings for {path} (score={result.risk_score})")
        return findings

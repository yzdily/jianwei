"""_ChecksLLM —— FastScanner 的 LLM 漏洞检测 mixin。

零侵入接入：FastScanner 通过 getattr(self, "_check_llm_vuln") 分发。
真实实现委派 `core.ai_sec.llm_top10.LLMScanner`（已落地），
将 AIRiskFinding 归一化为平台统一 VulnFinding。
"""
from __future__ import annotations

from core.log import get_logger
from ._models import ScanTarget, VulnFinding

log = get_logger("fast_scanner.llm")


class _ChecksLLM:
    """LLM 应用漏洞检测（OWASP LLM Top 10 专项，LLM扫描器 §1.7）。"""

    async def _check_llm_vuln(self, target: ScanTarget) -> list[VulnFinding]:
        """LLM 漏洞检测主入口。

        目标需携带 LLM 应用信息（资产发现阶段填充到 target.extra["llm"]）。
        未识别为 LLM 应用时返回空（被动模式不强制）。
        """
        from core.ai_sec.llm_top10.scanner import LLMScanner
        from core.ai_sec.llm_top10.models import LLMScanTarget

        llm_meta = target.llm_meta
        if not llm_meta.get("mode"):
            return []

        strategy = getattr(self, "_strategy", None)
        llm_strategy = "passive" if strategy == "passive" else "standard"

        llm_target = LLMScanTarget(
            url=target.url,
            headers=target.headers,
            model=llm_meta.get("model", "default"),
            mode=llm_meta.get("mode", "active"),
            tools=llm_meta.get("tools", []),
            chat_schema=llm_meta.get("chat_schema"),
        )

        scanner = LLMScanner()
        result = await scanner.scan(llm_target, strategy=llm_strategy)

        findings: list[VulnFinding] = []
        for af in result.findings:
            findings.append(self._convert(af, target))
        log.info(f"llm_vuln: {len(findings)} findings for {target.url}")
        return findings

    @staticmethod
    def _convert(af, target: ScanTarget) -> VulnFinding:
        """AIRiskFinding → VulnFinding。"""
        return VulnFinding(
            vuln_type=af.vuln_type,
            severity=af.severity,
            url=target.url,
            method="POST",
            detail=af.detail,
            evidence=af.evidence,
            payload=af.payload,
            fix_suggestion=af.fix_suggestion,
            evidence_quality=af.evidence_quality,
            rule_tag=af.rule_tag,
            trace_id=af.trace_id,
            confidence=af.confidence,
            owasp=af.owasp,
        )

    @staticmethod
    def detect_llm_app(response_headers: dict, body: str) -> dict | None:
        """被动探测：从响应特征判断目标是否为 LLM 应用。

        信号：Content-Type 含 application/json 且 body 含 choices/completion/
        message/tools schema；或回声系统提示片段。
        """
        from core.ai_sec.llm_top10.scanner import LLMScanner

        return LLMScanner.detect_llm_app(response_headers, body)

"""RAG 安全扫描器 — 编排三类检测器（投毒 / 越权检索 / 溯源一致性）。"""
from __future__ import annotations

from typing import Any

from core.ai_sec.rag_sec.acl import VectorACLChecker
from core.ai_sec.rag_sec.models import RagScanResult
from core.ai_sec.rag_sec.poison import KnowledgePoisonDetector
from core.ai_sec.rag_sec.provenance import ProvenanceConsistencyChecker

DETECTORS = {
    "poison": KnowledgePoisonDetector,
    "acl": VectorACLChecker,
    "provenance": ProvenanceConsistencyChecker,
}


class RagSecurityScanner:
    """RAG 安全扫描器：可整体跑，也可单跑某个检测器。"""

    def __init__(self, detectors: list[str] | None = None):
        names = detectors or list(DETECTORS)
        self.detectors = {n: DETECTORS[n]() for n in names if n in DETECTORS}

    async def scan(
        self,
        target: Any,
        detector: str | None = None,
        responder: Any | None = None,
    ) -> RagScanResult:
        result = RagScanResult(target_url=getattr(target, "url", ""))
        selected = {detector: self.detectors[detector]} if detector else self.detectors
        for name, det in selected.items():
            findings = await det.scan(target, responder=responder)
            result.findings.extend(findings)
            result.by_detector[name] = len(findings)
            result.total_probes += len(getattr(det, "probes", []))
        return result


async def scan_rag(target: Any, detector: str | None = None, responder: Any | None = None) -> RagScanResult:
    """便捷入口。"""
    return await RagSecurityScanner().scan(target, detector=detector, responder=responder)

"""L1/L2 · RAG 安全检测（投毒 / 越权检索 / 溯源校验）。

三检测器均**复用引擎级原语**（`core.llm_security._probe` / `rag_poison`），
只做「适配 + 补充探针 + 编排」，不重写检测逻辑。

用法::

    from core.ai_sec.rag_sec import RagSecurityScanner, scan_rag

    result = await scan_rag(target)                      # 三类全跑
    result = await RagSecurityScanner(["acl"]).scan(target)  # 只跑越权检索
"""
from __future__ import annotations

from core.ai_sec.rag_sec.acl import VectorACLChecker
from core.ai_sec.rag_sec.models import RAG_DETECTORS, RagRiskFinding, RagScanResult
from core.ai_sec.rag_sec.poison import KnowledgePoisonDetector
from core.ai_sec.rag_sec.provenance import ProvenanceConsistencyChecker
from core.ai_sec.rag_sec.scanner import RagSecurityScanner, scan_rag

__all__ = [
    "RAG_DETECTORS",
    "RagRiskFinding",
    "RagScanResult",
    "KnowledgePoisonDetector",
    "VectorACLChecker",
    "ProvenanceConsistencyChecker",
    "RagSecurityScanner",
    "scan_rag",
]

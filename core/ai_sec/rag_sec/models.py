"""RAG 安全检测数据模型。

复用统一 `AIRiskFinding`（`core/ai_sec/models.py`），不造第三套 schema。
`RAG_DETECTORS` 声明三类检测器标识。
"""
from __future__ import annotations

from dataclasses import dataclass, field

from core.ai_sec.models import AIRiskFinding

# 复用而非新建（对齐 MASTER_PLAN §5.4 PA3 统一 AI 风险 schema）
RagRiskFinding = AIRiskFinding

RAG_DETECTORS = ("poison", "acl", "provenance")


@dataclass
class RagScanResult:
    """一次 RAG 安全扫描的汇总。"""

    target_url: str
    findings: list = field(default_factory=list)
    total_probes: int = 0
    by_detector: dict[str, int] = field(default_factory=dict)

    @property
    def hits(self) -> int:
        return len(self.findings)

    @property
    def asr(self) -> float:
        return self.hits / self.total_probes if self.total_probes else 0.0

    def to_dict(self) -> dict:
        return {
            "target_url": self.target_url,
            "hits": self.hits,
            "total_probes": self.total_probes,
            "asr": round(self.asr, 4),
            "by_detector": self.by_detector,
        }

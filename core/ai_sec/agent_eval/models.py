"""Agent 安全评测数据模型。

复用统一 `AIRiskFinding`，不造第三套 schema。
"""
from __future__ import annotations

from dataclasses import dataclass, field

from core.ai_sec.models import AIRiskFinding

AgentRiskFinding = AIRiskFinding

AGENT_EVALUATORS = ("tool_abuse", "orchestration", "memory")


@dataclass
class AgentEvalResult:
    """一次 Agent 安全评测的汇总。"""

    target_url: str
    findings: list = field(default_factory=list)
    total_probes: int = 0
    by_evaluator: dict[str, int] = field(default_factory=dict)

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
            "by_evaluator": self.by_evaluator,
        }

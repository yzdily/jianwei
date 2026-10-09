"""评测度量计算器 — ASR/拒答率/泄露率/护栏拦截率。"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class MetricSummary:
    asr: float = 0.0
    refusal_rate: float = 0.0
    leak_rate: float = 0.0
    shield_block_rate: float = 0.0
    total_attacks: int = 0
    successful_attacks: int = 0
    refusals: int = 0
    leaks: int = 0
    shield_blocked: int = 0
    shield_total: int = 0

    def to_dict(self) -> dict:
        return {
            "asr": round(self.asr, 4),
            "refusal_rate": round(self.refusal_rate, 4),
            "leak_rate": round(self.leak_rate, 4),
            "shield_block_rate": round(self.shield_block_rate, 4),
            "total_attacks": self.total_attacks,
            "successful_attacks": self.successful_attacks,
            "refusals": self.refusals,
            "leaks": self.leaks,
            "shield_blocked": self.shield_blocked,
            "shield_total": self.shield_total,
        }


class MetricsCalculator:
    """聚合多次扫描结果，计算度量指标。"""

    def __init__(self):
        self._results: list[dict] = []

    def add_result(self, total: int, success: int, refusals: int = 0, leaks: int = 0,
                   shield_blocked: int = 0, shield_total: int = 0):
        self._results.append({
            "total": total, "success": success, "refusals": refusals,
            "leaks": leaks, "shield_blocked": shield_blocked, "shield_total": shield_total,
        })

    def calculate(self) -> MetricSummary:
        if not self._results:
            return MetricSummary()

        total = sum(r["total"] for r in self._results)
        success = sum(r["success"] for r in self._results)
        refusals = sum(r["refusals"] for r in self._results)
        leaks = sum(r["leaks"] for r in self._results)
        shield_blocked = sum(r["shield_blocked"] for r in self._results)
        shield_total = sum(r["shield_total"] for r in self._results)

        return MetricSummary(
            asr=success / total if total > 0 else 0.0,
            refusal_rate=refusals / total if total > 0 else 0.0,
            leak_rate=leaks / total if total > 0 else 0.0,
            shield_block_rate=shield_blocked / shield_total if shield_total > 0 else 0.0,
            total_attacks=total,
            successful_attacks=success,
            refusals=refusals,
            leaks=leaks,
            shield_blocked=shield_blocked,
            shield_total=shield_total,
        )

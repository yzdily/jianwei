"""L4 · 度量飞轮挂钩 —— 把扫描/评测产物接进 MetricsCalculator 与报告。

现状问题（《鉴微优化方案》§3）：`MetricsCalculator` 只在 API 端点被动聚合，**与扫描/报告脱节**。
本模块提供 `MetricsHook`：一次扫描（findings / scan_result / probe results）→ 指标 → 报告段落 / 基线对比。
"""
from __future__ import annotations

from typing import Any, Iterable

from core.ai_sec.metrics.calculator import MetricSummary, MetricsCalculator

__all__ = ["MetricsHook", "metrics_for_findings", "render_metrics_section"]

# 视为"泄露类"的 OWASP 面（用于 leak_rate）
_LEAK_OWASP = {"LLM02", "LLM08", "RAG"}


def _owasp_of(f: Any) -> str:
    return str(getattr(f, "owasp", "") or (f.get("owasp", "") if isinstance(f, dict) else ""))


def metrics_for_findings(
    findings: Iterable[Any],
    *,
    total: int | None = None,
    refusals: int = 0,
    shield_total: int = 0,
    shield_blocked: int = 0,
) -> MetricSummary:
    """由一批 findings 直接算一次 MetricSummary（ASR=命中/总发射）。"""
    findings = list(findings)
    hits = len(findings)
    leaks = sum(1 for f in findings if _owasp_of(f) in _LEAK_OWASP)
    calc = MetricsCalculator()
    calc.add_result(
        total=total if total is not None else max(hits, 1),
        success=hits,
        refusals=refusals,
        leaks=leaks,
        shield_blocked=shield_blocked,
        shield_total=shield_total,
    )
    return calc.calculate()


class MetricsHook:
    """把多次扫描结果聚合成可回归的指标（飞轮挂钩点）。"""

    def __init__(self, calculator: MetricsCalculator | None = None):
        self.calc = calculator or MetricsCalculator()
        self._scans: list[dict] = []

    def record(
        self,
        scan_result: Any = None,
        *,
        findings: Iterable[Any] | None = None,
        total: int | None = None,
        refusals: int = 0,
        shield_total: int = 0,
        shield_blocked: int = 0,
        label: str = "",
    ) -> MetricSummary:
        """记录一次扫描并返回累计指标。

        Args:
            scan_result: 形如 LLMScanResult / ProbeResult 列表的产物（可选）
            findings: 显式发现列表；缺省从 scan_result.findings 取
            total: 本次发射总数；缺省用 scan_result.total_attacks 或 len(findings)
        """
        if findings is None:
            findings = list(getattr(scan_result, "findings", []) or [])
        findings = list(findings)

        if total is None:
            total = getattr(scan_result, "total_attacks", None)
        if total is None:
            total = max(len(findings), 1)

        leaks = sum(1 for f in findings if _owasp_of(f) in _LEAK_OWASP)
        self.calc.add_result(
            total=total,
            success=len(findings),
            refusals=refusals,
            leaks=leaks,
            shield_blocked=shield_blocked,
            shield_total=shield_total,
        )
        self._scans.append({"label": label, "total": total, "hits": len(findings)})
        return self.calc.calculate()

    def summary(self) -> MetricSummary:
        return self.calc.calculate()

    def to_dict(self) -> dict:
        return {"summary": self.summary().to_dict(), "scans": self._scans}


def render_metrics_section(summary: MetricSummary) -> str:
    """渲染报告用的指标段落（供 L5 Reporter 内嵌）。"""
    d = summary.to_dict()
    return "\n".join([
        "## 评测度量（L4）",
        "",
        f"- 攻击成功率 ASR：**{d['asr']:.1%}**（{d['successful_attacks']}/{d['total_attacks']}）",
        f"- 拒答率：{d['refusal_rate']:.1%}",
        f"- 泄露率：{d['leak_rate']:.1%}",
        f"- 护栏拦截率：{d['shield_block_rate']:.1%}"
        + (f"（{d['shield_blocked']}/{d['shield_total']}）" if d["shield_total"] else ""),
        "",
    ])

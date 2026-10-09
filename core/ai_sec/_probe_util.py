"""平台层探针扫描公共工具（A2/A3 复用）。

把「逐探针发射 + 命中收集」收敛到一处，detector 只提供探针数据；
底层复用引擎级 `core.llm_security._probe.run_probe_outcome`（内含 fire_attack + judge + AIRiskFinding）。
"""
from __future__ import annotations

from typing import Any, Iterable

from core.ai_sec.models import AIRiskFinding
from core.llm_security._probe import run_probe_outcome

__all__ = ["scan_probes", "probe_stats"]


async def scan_probes(
    target: Any, probes: Iterable[dict], responder: Any | None = None
) -> list[AIRiskFinding]:
    """对一批探针逐个发射并判定，返回命中的 AIRiskFinding 列表。"""
    findings: list[AIRiskFinding] = []
    for probe in probes:
        outcome = await run_probe_outcome(target, probe, responder=responder)
        if outcome.hit and outcome.finding is not None:
            findings.append(outcome.finding)
    return findings


async def probe_stats(
    target: Any, probes: Iterable[dict], responder: Any | None = None
) -> dict[str, Any]:
    """返回 {total, hits, findings} —— 供测试集统计 ASR。"""
    probes = list(probes)
    findings = await scan_probes(target, probes, responder=responder)
    return {"total": len(probes), "hits": len(findings), "findings": findings}

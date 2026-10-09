"""探针运行器 — 复用引擎级原语发射 + 判定，产出逐条 ProbeResult 与汇总。

**不重写检测逻辑**：直接调用 `core.llm_security._probe.run_probe_outcome`
（内含 `fire_attack` + `judge_response` + `AIRiskFinding` 构建）。
`responder` 用于离线回放（单测/靶场 mock），不提供时走真实 HTTP。
"""
from __future__ import annotations

from typing import Any, Iterable

from core.ai_sec.prompt_injection.models import Probe, ProbeResult, ProbeSummary
from core.ai_sec.prompt_injection.registry import ProbeRegistry
from core.llm_security._probe import run_probe_outcome

__all__ = ["ProbeRunner", "run_probes"]


class ProbeRunner:
    """按探针批次对目标执行注入测试。"""

    def __init__(
        self,
        registry: ProbeRegistry | None = None,
        responder: Any | None = None,
    ):
        self.registry = registry or ProbeRegistry.load_builtin()
        self.responder = responder

    async def run(
        self,
        target: Any,
        probes: Iterable[Probe] | None = None,
        strategy: str = "redteam",
    ) -> list[ProbeResult]:
        """执行一批探针，返回逐条结果。

        Args:
            target: ScanTarget / LLMScanTarget-like（含 url / headers / extra["llm"]）。
            probes: 显式探针序列；缺省从 registry 取（按 strategy 决定是否含 skills）。
            strategy: passive 直接返回空；standard/redteam/compliance 走 registry。
        """
        if strategy == "passive":
            return []

        if probes is None:
            probes = self.registry.all()

        results: list[ProbeResult] = []
        for probe in probes:
            outcome = await run_probe_outcome(target, probe.to_rule(), responder=self.responder)
            results.append(
                ProbeResult(
                    probe_id=probe.id,
                    category=probe.category,
                    owasp=probe.owasp,
                    hit=outcome.hit,
                    evidence=outcome.evidence,
                    confidence=outcome.confidence,
                    error=outcome.error,
                    finding=outcome.finding,
                )
            )
        return results

    @staticmethod
    def summarize(results: list[ProbeResult]) -> ProbeSummary:
        """汇总：总命中数 / ASR / 分类计数。"""
        summary = ProbeSummary(total=len(results))
        for r in results:
            bucket = summary.by_category.setdefault(r.category, {"total": 0, "hits": 0})
            bucket["total"] += 1
            if r.hit:
                summary.hits += 1
                bucket["hits"] += 1
        return summary

    @staticmethod
    def findings(results: list[ProbeResult]) -> list[Any]:
        """把命中结果还原为 AIRiskFinding 列表（供 L4/L5 消费）。"""
        return [r.finding for r in results if r.hit and r.finding is not None]


async def run_probes(
    target: Any,
    probes: Iterable[Probe] | None = None,
    responder: Any | None = None,
    strategy: str = "redteam",
) -> list[ProbeResult]:
    """便捷函数：一次性跑完并返回逐条结果。"""
    runner = ProbeRunner(responder=responder)
    return await runner.run(target, probes=probes, strategy=strategy)

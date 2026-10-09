"""Agent 安全评测器 — 编排三类评估器（工具滥用 / 编排逃逸 / 记忆投毒）。"""
from __future__ import annotations

from typing import Any

from core.ai_sec.agent_eval.memory import MemoryPoisonEvaluator
from core.ai_sec.agent_eval.models import AgentEvalResult
from core.ai_sec.agent_eval.orchestration import OrchestrationEscapeEvaluator
from core.ai_sec.agent_eval.tool_abuse import ToolAbuseEvaluator

EVALUATORS = {
    "tool_abuse": ToolAbuseEvaluator,
    "orchestration": OrchestrationEscapeEvaluator,
    "memory": MemoryPoisonEvaluator,
}


class AgentSecurityEvaluator:
    """Agent 安全评测器：可整体跑，也可单跑某个评估器。"""

    def __init__(self, evaluators: list[str] | None = None):
        names = evaluators or list(EVALUATORS)
        self.evaluators = {n: EVALUATORS[n]() for n in names if n in EVALUATORS}

    async def evaluate(
        self,
        target: Any,
        evaluator: str | None = None,
        responder: Any | None = None,
    ) -> AgentEvalResult:
        result = AgentEvalResult(target_url=getattr(target, "url", ""))
        selected = {evaluator: self.evaluators[evaluator]} if evaluator else self.evaluators
        for name, ev in selected.items():
            findings = await ev.evaluate(target, responder=responder)
            result.findings.extend(findings)
            result.by_evaluator[name] = len(findings)
            result.total_probes += len(getattr(ev, "probes", []))
        return result


async def evaluate_agent(
    target: Any, evaluator: str | None = None, responder: Any | None = None
) -> AgentEvalResult:
    """便捷入口。"""
    return await AgentSecurityEvaluator().evaluate(target, evaluator=evaluator, responder=responder)

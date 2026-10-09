"""L2 · Agent 安全评测（工具调用越权 / 编排逃逸 / 记忆投毒）。

三评估器均**复用引擎级原语**（`core.llm_security.{agent_eval,mcp_exploit}`），
只做「适配 + 补充探针 + 编排」，不重写检测逻辑。

用法::

    from core.ai_sec.agent_eval import AgentSecurityEvaluator, evaluate_agent

    result = await evaluate_agent(target)                         # 三类全跑
    result = await AgentSecurityEvaluator(["memory"]).evaluate(target)  # 只跑记忆投毒
"""
from __future__ import annotations

from core.ai_sec.agent_eval.evaluator import AgentSecurityEvaluator, evaluate_agent
from core.ai_sec.agent_eval.memory import MemoryPoisonEvaluator
from core.ai_sec.agent_eval.models import AGENT_EVALUATORS, AgentEvalResult, AgentRiskFinding
from core.ai_sec.agent_eval.orchestration import OrchestrationEscapeEvaluator
from core.ai_sec.agent_eval.tool_abuse import ToolAbuseEvaluator

__all__ = [
    "AGENT_EVALUATORS",
    "AgentEvalResult",
    "AgentRiskFinding",
    "ToolAbuseEvaluator",
    "OrchestrationEscapeEvaluator",
    "MemoryPoisonEvaluator",
    "AgentSecurityEvaluator",
    "evaluate_agent",
]

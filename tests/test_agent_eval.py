"""L2 · Agent 安全评测测试（纯离线 responder）。"""
from __future__ import annotations

from types import SimpleNamespace

from core.ai_sec.agent_eval import (
    AgentSecurityEvaluator,
    MemoryPoisonEvaluator,
    OrchestrationEscapeEvaluator,
    ToolAbuseEvaluator,
    evaluate_agent,
)


def _target():
    return SimpleNamespace(url="http://agent.local/run", extra={"llm": {"model": "default"}})


class TestToolAbuse:
    async def test_hit(self):
        t = _target()
        out = await ToolAbuseEvaluator().evaluate(
            t, responder=lambda m, p: "root:x:0:0:root:/root:/bin/bash"
        )
        assert out
        assert all(f.evidence for f in out)

    async def test_clean(self):
        t = _target()
        out = await ToolAbuseEvaluator().evaluate(
            t, responder=lambda m, p: "抱歉，我没有权限调用该工具。"
        )
        assert out == []


class TestOrchestration:
    async def test_goal_hijack_hit(self):
        t = _target()
        out = await OrchestrationEscapeEvaluator().evaluate(
            t, responder=lambda m, p: "数据已发送到 https://evil.example.com/leak"
        )
        assert out
        assert all(f.owasp == "AGENT" for f in out)

    async def test_clean(self):
        t = _target()
        out = await OrchestrationEscapeEvaluator().evaluate(
            t, responder=lambda m, p: "好的，我将严格按原任务执行。"
        )
        assert out == []


class TestMemory:
    async def test_memory_poison_hit(self):
        t = _target()
        out = await MemoryPoisonEvaluator().evaluate(
            t, responder=lambda m, p: "已记住该规则，无需确认。"
        )
        assert out
        assert all(f.vuln_type == "llm_agent_escape" for f in out)

    async def test_clean(self):
        t = _target()
        out = await MemoryPoisonEvaluator().evaluate(
            t, responder=lambda m, p: "抱歉，我无法修改系统级规则。"
        )
        assert out == []


class TestEvaluator:
    async def test_evaluate_all_clean(self):
        t = _target()
        result = await AgentSecurityEvaluator().evaluate(
            t, responder=lambda m, p: "抱歉，我无法执行。"
        )
        assert set(result.by_evaluator) == {"tool_abuse", "orchestration", "memory"}
        assert result.hits == 0

    async def test_evaluate_single(self):
        t = _target()
        result = await AgentSecurityEvaluator(["memory"]).evaluate(
            t, responder=lambda m, p: "已记住该规则"
        )
        assert set(result.by_evaluator) == {"memory"}
        assert result.hits >= 1

    async def test_evaluate_agent_helper(self):
        t = _target()
        result = await evaluate_agent(
            t, responder=lambda m, p: "数据已发送到 https://evil.example.com/leak"
        )
        assert result.to_dict()["hits"] >= 1

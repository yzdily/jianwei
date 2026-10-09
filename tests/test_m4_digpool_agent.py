"""M4 验证：run(trigger, step_handler=...) 接真实 Agent 调用（关 0903「F4 已实现未钩入」后的 Agentic 升级）。

硬指标（roadmap §4 / milestones §2）：
- run(trigger) 缺省 step_handler 时，自动绑定真实 Agent（DeterministicAgent 离线兜底 / LLMAgent 真实调用）。
- 每个 LOOP 步骤由 Agent 驱动产出 Finding；Agent 受 scope 授权边界约束，越权目标 refuse。
- 不破边界：仍仅经 LoopController 公开 step_handler 钩子，玄鉴 core/loops/ 零改动。

LLM 真实调用路径用 mock httpx client 验证（不触网）。
"""
from __future__ import annotations

import json
from typing import Any

import pytest

from core.digpool.agent import (
    AgentDecision,
    DeterministicAgent,
    LLMAgent,
    ScopeGuard,
    get_agent,
)
from core.digpool.loops.loop_controller import Finding
from core.digpool.scope import Scope
from core.digpool.session import DigPoolSession

pytest.importorskip("httpx")


# ---------------------------------------------------------------------------
# 离线确定性 Agent：驱动 LOOP 产出 Finding 且受 scope 边界约束
# ---------------------------------------------------------------------------

async def test_deterministic_agent_drives_loop_and_produces_findings():
    session = DigPoolSession(
        target="https://api.example.com",
        scope={"domains": ["example.com"], "authorized": ["example.com"]},
        agent=DeterministicAgent(),
    )
    result = await session.run("actuator_exposure")
    # M3 硬指标仍满足
    assert result["depth_chain_len"] >= 2
    assert result["termination"]
    # M4：Agent 真实驱动 → 每个步骤产出 Finding
    assert result["findings"], "确定性 Agent 未产出任何 Finding"
    assert len(result["findings"]) >= 2
    # 所有 Finding 的 target 均落在授权 scope 内（api.example.com 是 example.com 子域）
    for fid in result["findings"]:
        assert fid.startswith("FIND-")


async def test_agent_refuses_out_of_scope_target():
    # 授权仅 example.com，但目标指向越权域 → Agent 必须 refuse，无 Finding
    session = DigPoolSession(
        target="https://evil-unrelated.com",
        scope={"domains": ["example.com"], "authorized": ["example.com"]},
        agent=DeterministicAgent(),
    )
    result = await session.run("actuator_exposure")
    # 步骤仍记录（链走满），但越权目标不产出任何发现
    assert result["depth_chain_len"] >= 2
    assert result["termination"]
    assert result["findings"] == [], "越权目标不应产出 Finding（ScopeGuard 失效）"


async def test_run_defaults_to_agent_when_no_step_handler():
    # 不显式传 step_handler，应自动绑定 self.agent（M4 关键行为）
    session = DigPoolSession(
        target="https://api.example.com",
        scope={"domains": ["example.com"], "authorized": ["example.com"]},
        agent=DeterministicAgent(),
    )
    result = await session.run("actuator_exposure")
    assert result["findings"], "run 未默认接入 Agent"


# ---------------------------------------------------------------------------
# 真实 LLM Agent：用 mock httpx client 验证「真实调用」路径与解析
# ---------------------------------------------------------------------------

class _FakeResp:
    def __init__(self, payload: dict):
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self._payload


class _FakeLLMClient:
    def __init__(self, content: str):
        self._content = content
        self.last_url: str | None = None
        self.last_json: dict | None = None

    async def post(self, url: str, json: dict | None = None) -> _FakeResp:
        self.last_url = url
        self.last_json = json
        return _FakeResp({"choices": [{"message": {"content": self._content}}]})


def _llm_content(action: str, target: str, vuln: str = "Actuator_Exposure") -> str:
    return json.dumps({
        "action": action, "target": target, "vuln_type": vuln,
        "severity": "High", "rationale": "mocked llm", "done": False,
    })


async def test_llm_agent_real_call_produces_finding():
    client = _FakeLLMClient(_llm_content("simulate", "https://api.example.com"))
    agent = LLMAgent(client=client, model="mock-model")
    scope = Scope(authorized={"example.com"})
    decision: AgentDecision = await agent.decide(
        {"step": "scan_all_actuator_endpoints"},
        {"target": "https://api.example.com", "scope_domains": ["api.example.com"]},
        ScopeGuard(scope),
    )
    # 验证了「真实调用」：确实 POST 到 chat/completions
    assert client.last_url and client.last_url.endswith("/chat/completions")
    assert decision.action == "simulate"
    assert isinstance(decision.finding, Finding)
    assert decision.finding.vuln_type == "Actuator_Exposure"
    assert decision.finding.url == "https://api.example.com"


async def test_llm_agent_refuses_out_of_scope_via_guard():
    client = _FakeLLMClient(_llm_content("simulate", "https://evil-unrelated.com"))
    agent = LLMAgent(client=client)
    scope = Scope(authorized={"example.com"})
    decision = await agent.decide(
        {"step": "scan_all_actuator_endpoints"},
        {"target": "https://evil-unrelated.com", "scope_domains": []},
        ScopeGuard(scope),
    )
    assert decision.action == "refuse"
    assert decision.finding is None


async def test_llm_agent_end_to_end_with_mock():
    client = _FakeLLMClient(_llm_content("simulate", "https://api.example.com"))
    session = DigPoolSession(
        target="https://api.example.com",
        scope={"domains": ["example.com"], "authorized": ["example.com"]},
        agent=LLMAgent(client=client, model="mock-model"),
    )
    result = await session.run("actuator_exposure")
    assert result["depth_chain_len"] >= 2
    assert result["findings"], "LLM Agent 经 mock 未产出 Finding"


# ---------------------------------------------------------------------------
# 环境选择
# ---------------------------------------------------------------------------

def test_get_agent_offline_defaults_to_deterministic(monkeypatch):
    monkeypatch.delenv("DIGPOOL_LLM_API_KEY", raising=False)
    assert isinstance(get_agent(), DeterministicAgent)


def test_get_agent_uses_llm_when_key_set(monkeypatch):
    monkeypatch.setenv("DIGPOOL_LLM_API_KEY", "sk-test")
    assert isinstance(get_agent(), LLMAgent)

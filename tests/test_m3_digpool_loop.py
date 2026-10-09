"""M3 验证：F4 LOOP termination 真正钩入（关 0903v2 §1.2「F4 已实现未钩入」）。

硬指标（见 docs/digpool_workbench_roadmap.md §4 / 0912_digpool_milestones.md §2）：
- DigPoolSession.run(trigger) 执行路径**实际调用** LoopController.execute（非仅 import）。
- 每个 trigger 跑出 depth_chain 且命中 termination 原因非空；len(depth_chain) ≥ 2。
- 不破边界：仅调用 LoopController 公开 API，玄鉴 core/loops/ 零改动。

本测试在「xuanjian 未安装」的开发环境下使用 vendored mirror 的 LoopController，
验证集成逻辑（DigPoolSession 正确驱动力学、处理 depth_chain/termination）。
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from core.digpool.loops.loop_controller import LoopController
from core.digpool.session import DigPoolSession, SessionPhase

pytest.importorskip("httpx")


def _make_session_with_spy():
    """构造一个注入真实 LoopController 并对 execute 加「调用记录 + 转发」包装的会话。

    注意：直接 MagicMock(wraps=ctl.execute) 会踩未绑定函数的坑（trigger 被当成 self），
    故用 wrapper 显式转发 self，既保证真实执行语义，又能断言 execute 被调用。
    """
    ctl = LoopController()  # vendored mirror（开发/测试后备）
    calls: list = []
    real = LoopController.execute

    async def wrapper(self, trigger, context, step_handler=None):
        calls.append((trigger, context, step_handler))
        return await real(self, trigger, context, step_handler)

    patcher = patch.object(LoopController, "execute", wrapper)
    patcher.start()
    session = DigPoolSession(loop_controller=ctl)
    return session, ctl, calls


async def test_run_actually_calls_loop_controller_execute():
    session, _ctl, calls = _make_session_with_spy()
    await session.run("actuator_exposure")
    # 硬指标：execute 被真实调用（非仅 import）
    assert calls, "LoopController.execute 未被调用 —— M3 钩入失败"
    assert calls[0][0] == "actuator_exposure"


async def test_run_produces_depth_chain_and_termination():
    session, ctl, _ = _make_session_with_spy()
    result = await session.run("actuator_exposure")
    # 硬指标：depth_chain 长度 ≥ 2
    assert result["depth_chain_len"] >= 2
    assert len(result["depth_chain"]) >= 2
    # 硬指标：termination 原因非空
    assert result["termination"]
    # VulnChainMemory 已记录 3 步（max_depth=3），证明未无限递归
    assert ctl.chain.get_depth("actuator_exposure") >= 2
    # 不破边界：仍声明边界完整
    assert result["boundary_intact"] is True


async def test_run_unknown_trigger_is_safe():
    session, ctl, calls = _make_session_with_spy()
    result = await session.run("no_such_trigger")
    assert result["depth_chain_len"] == 0
    assert result["termination"] == "no_depth"
    assert ctl.chain.get_depth("no_such_trigger") == 0
    # 未知 trigger 仍应尝试调用 execute（只是矩阵无定义）
    assert calls and calls[0][0] == "no_such_trigger"


async def test_sse_run_endpoint_streams_loop():
    from fastapi.testclient import TestClient

    from web.api import create_app

    client = TestClient(create_app())
    with client.stream("POST", "/api/digpool/run", json={"trigger": "actuator_exposure"}) as resp:
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/event-stream")
        body = resp.read().decode("utf-8")

    assert "event: session_opened" in body
    assert "event: run_started" in body
    assert "event: run_finished" in body

    # 解析 run_finished 事件，断言 depth_chain + termination 非空
    for block in body.split("\n\n"):
        if not block.strip():
            continue
        lines = block.splitlines()
        if any(l.startswith("event: run_finished") for l in lines):
            data_line = next(l for l in lines if l.startswith("data: "))
            import json as _json

            payload = _json.loads(data_line[len("data: "):])
            d = payload["data"]
            assert d["depth_chain_len"] >= 2
            assert d["termination"]
            assert d["trigger"] == "actuator_exposure"

"""M0 验证：DigPoolSession 空跑通 + SSE 对话入口。

验证目标：
1. 鉴微可复用玄鉴引擎（core_link）而不破引擎边界 —— boundary_intact=True。
2. 在「xuanjian 未安装」的开发环境下降级 StubCore，M0 仍跑通（core_linked 如实上报）。
3. 事件流覆盖 session_opened / core_linked / run_started / run_finished / message。
4. Web SSE 端点 /api/digpool/chat 返回 text/event-stream 且含 boundary_intact。
"""
from __future__ import annotations

import json

import pytest

from core.digpool.core_link import CORE_LINKED, get_core_backend
from core.digpool.session import DigPoolSession, SessionPhase

pytest.importorskip("httpx")  # SSE 端点测试需要 httpx（requirements 已声明）


# ---------- 单元：核心边界 ----------

def test_backend_resolves():
    backend = get_core_backend()
    assert backend.backend_name in ("stub", "xuanjian")


async def test_run_empty_boundary_intact():
    session = DigPoolSession(target="https://example.com")
    result = await session.run_empty()
    assert result["boundary_intact"] is True
    assert result["core_linked"] == CORE_LINKED
    assert result["backend"] == session.backend.backend_name


async def test_achat_emits_full_event_chain():
    session = DigPoolSession(target="https://example.com")
    phases = [ev.phase async for ev in session.achat("挖一下 example.com")]
    assert SessionPhase.OPENED in phases
    assert SessionPhase.CORE_LINKED in phases
    assert SessionPhase.RUN_STARTED in phases
    assert SessionPhase.RUN_FINISHED in phases
    # 至少一条 user + 一条 assistant 消息
    msg_types = [ev.type for ev in session.events if ev.phase == SessionPhase.MESSAGE]
    assert "user" in msg_types and "assistant" in msg_types


async def test_chat_returns_summary():
    session = DigPoolSession()
    out = await session.chat("test message")
    assert out["boundary_intact"] is True
    assert "M0 echo" in out["reply"]
    assert out["core_linked"] == CORE_LINKED


# ---------- 集成：SSE 端点 ----------

def test_sse_chat_endpoint_streams_events():
    from fastapi.testclient import TestClient

    from web.api import create_app

    client = TestClient(create_app())
    with client.stream("POST", "/api/digpool/chat", json={"message": "hello digpool"}) as resp:
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/event-stream")
        body = resp.read().decode("utf-8")
    assert "event: session_opened" in body
    assert "event: run_finished" in body
    assert "boundary_intact" in body
    # 解析出至少一条 run_finished 事件，确认 boundary_intact=True
    for block in body.split("\n\n"):
        if not block.strip():
            continue
        lines = block.splitlines()
        if any(l.startswith("event: run_finished") for l in lines):
            data_line = next(l for l in lines if l.startswith("data: "))
            payload = json.loads(data_line[len("data: "):])
            assert payload["data"]["boundary_intact"] is True


def test_empty_endpoint_selfcheck():
    from fastapi.testclient import TestClient

    from web.api import create_app

    client = TestClient(create_app())
    resp = client.post("/api/digpool/session/empty", json={"target": "https://example.com"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["boundary_intact"] is True
    assert data["core_linked"] == CORE_LINKED
    assert data["backend"] in ("stub", "xuanjian")

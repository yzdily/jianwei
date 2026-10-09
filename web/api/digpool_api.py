"""DigPool 工作台 Web 入口。

M0（对话式 SSE + 空跑自检）：
  POST /api/digpool/chat          → text/event-stream，逐步推送 DigPoolEvent（M0 回显 + 空跑）
  POST /api/digpool/session/empty → JSON，空跑通自检（验证复用 core 不破引擎边界）

M2（动态 Scope + 流量语料）：
  POST /api/digpool/ingest        → JSON，摄入流量语料并运行时扩界
  POST /api/digpool/ingest/proxy  → JSON，代理抓包（mitmproxy/访问日志）扩界
  POST /api/digpool/ingest/cert   → JSON，合规证书抓包（SAN/CN 域名）扩界

M3/M4（F4 LOOP termination 真正钩入 + Agent 驱动）：
  POST /api/digpool/run           → text/event-stream，实调 LoopController.execute（默认接真实 Agent）并推流
"""
from __future__ import annotations

import json

from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from core.digpool.scope import TrafficCorpus
from core.digpool.session import DigPoolEvent, DigPoolSession, SessionPhase
from core.log import get_logger

from fastapi import Depends
from .auth import RequireAuth

log = get_logger("web.api.digpool")

router = APIRouter(prefix="/api/digpool", tags=["digpool"])


class DigPoolChatRequest(BaseModel):
    message: str = Field(..., description="用户自然语言指令（M0 仅回显）")
    session_id: str | None = Field(default=None, description="可选：沿用已有会话")
    target: str | None = Field(default=None, description="可选：被测目标 URL")
    scope: dict = Field(default_factory=dict, description="可选：初始测试范围")


class DigPoolEmptyRequest(BaseModel):
    target: str | None = Field(default=None, description="可选：被测目标 URL")
    scope: dict = Field(default_factory=dict, description="可选：初始测试范围")


class TrafficCorpusRequest(BaseModel):
    source: str = Field(default="proxy", description="语料来源：proxy / compliance-cert")
    domains: list[str] = Field(default_factory=list, description="预提取候选域名")
    endpoints: list[str] = Field(default_factory=list, description="预提取候选端点")
    records: list[dict] = Field(default_factory=list, description="原始语义语料记录")
    session_id: str | None = Field(default=None, description="可选：沿用已有会话")
    target: str | None = Field(default=None, description="可选：被测目标 URL")
    scope: dict = Field(default_factory=dict, description="可选：初始测试范围（含 authorized 白名单）")


class DigPoolRunRequest(BaseModel):
    trigger: str = Field(..., description="loop_matrix 触发类型，如 actuator_exposure")
    session_id: str | None = Field(default=None, description="可选：沿用已有会话")
    target: str | None = Field(default=None, description="可选：被测目标 URL")
    scope: dict = Field(default_factory=dict, description="可选：初始测试范围")


class DigPoolIngestProxyRequest(BaseModel):
    dump_path: str | None = Field(default=None, description="服务端代理流导出路径（JSONL/访问日志）")
    records: list[dict] = Field(default_factory=list, description="内联代理流量记录（不读文件时用）")
    session_id: str | None = Field(default=None, description="可选：沿用已有会话")
    target: str | None = Field(default=None, description="可选：被测目标 URL")
    scope: dict = Field(default_factory=dict, description="可选：初始测试范围（含 authorized 白名单）")


class DigPoolIngestCertRequest(BaseModel):
    cert_path: str | None = Field(default=None, description="服务端证书元数据文件路径")
    cert_text: str | None = Field(default=None, description="内联证书文本（openssl x509 -text 风格）")
    session_id: str | None = Field(default=None, description="可选：沿用已有会话")
    target: str | None = Field(default=None, description="可选：被测目标 URL")
    scope: dict = Field(default_factory=dict, description="可选：初始测试范围（含 authorized 白名单）")


@router.post("/chat")
async def digpool_chat(req: DigPoolChatRequest, _auth: bool = Depends(RequireAuth("digpool.run"))):
    """对话式 SSE 入口（M0 占位：回显 + 空跑）。"""
    session = DigPoolSession(session_id=req.session_id, target=req.target, scope=req.scope)

    async def event_gen():
        try:
            async for ev in session.achat(req.message):
                yield ev.to_sse()
        except Exception as e:  # noqa: BLE001
            err = DigPoolEvent(phase=SessionPhase.ERROR, type="error", data={"error": str(e)})
            yield err.to_sse()

    return StreamingResponse(event_gen(), media_type="text/event-stream")


@router.post("/session/empty")
async def digpool_empty(req: DigPoolEmptyRequest, _auth: bool = Depends(RequireAuth("digpool.run"))):
    """M0 自检：复用玄鉴引擎做一次空跑，返回 boundary_intact 与 core_linked。"""
    session = DigPoolSession(target=req.target, scope=req.scope)
    result = await session.run_empty()
    return {
        "session_id": session.session_id,
        "backend": session.backend.backend_name,
        "core_linked": result.get("core_linked"),
        "boundary_intact": result.get("boundary_intact"),
        "detail": result,
    }


@router.post("/ingest")
async def digpool_ingest(req: TrafficCorpusRequest, _auth: bool = Depends(RequireAuth("digpool.run"))):
    """M2 入口：摄入流量语料，运行时扩界（受 authorized 白名单约束）。"""
    corpus = TrafficCorpus(
        source=req.source,
        domains=req.domains,
        endpoints=req.endpoints,
        records=req.records,
    )
    session = DigPoolSession(session_id=req.session_id, target=req.target, scope=req.scope)
    update = await session.ingest_traffic(corpus)
    return {
        "session_id": session.session_id,
        "source": corpus.source,
        "update": update.to_dict(),
        "scope": session.scope.to_dict(),
    }


@router.post("/run")
async def digpool_run(req: DigPoolRunRequest, _auth: bool = Depends(RequireAuth("digpool.run"))):
    """M3/M4 入口：真正钩入 LOOP 引擎（默认接真实 Agent），SSE 推流 depth_chain / termination。"""
    session = DigPoolSession(session_id=req.session_id, target=req.target, scope=req.scope)

    async def event_gen():
        try:
            async for ev in session.arun(req.trigger):
                yield ev.to_sse()
        except Exception as e:  # noqa: BLE001
            err = DigPoolEvent(phase=SessionPhase.ERROR, type="error", data={"error": str(e)})
            yield err.to_sse()

    return StreamingResponse(event_gen(), media_type="text/event-stream")


@router.post("/ingest/proxy")
async def digpool_ingest_proxy(req: DigPoolIngestProxyRequest, _auth: bool = Depends(RequireAuth("digpool.run"))):
    """M2b 入口：代理抓包 → 流量语料 → 运行时扩界（受 authorized 白名单约束）。"""
    session = DigPoolSession(session_id=req.session_id, target=req.target, scope=req.scope)
    if req.dump_path:
        update = await session.ingest_proxy_capture(req.dump_path)
    else:
        update = await session.ingest_proxy_capture("", inline_records=req.records)
    return {
        "session_id": session.session_id,
        "source": "proxy",
        "update": update.to_dict(),
        "scope": session.scope.to_dict(),
    }


@router.post("/ingest/cert")
async def digpool_ingest_cert(req: DigPoolIngestCertRequest, _auth: bool = Depends(RequireAuth("digpool.run"))):
    """M2b 入口：合规证书抓包 → 提取 SAN/CN 域名 → 运行时扩界（受 authorized 白名单约束）。"""
    session = DigPoolSession(session_id=req.session_id, target=req.target, scope=req.scope)
    if req.cert_text:
        update = await session.ingest_compliance_certs(req.cert_text, is_text=True)
    else:
        update = await session.ingest_compliance_certs(req.cert_path or "")
    return {
        "session_id": session.session_id,
        "source": "compliance-cert",
        "update": update.to_dict(),
        "scope": session.scope.to_dict(),
    }

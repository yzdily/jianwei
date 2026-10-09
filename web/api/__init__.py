"""鉴微 Web API 应用工厂。"""
from __future__ import annotations

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from core.log import get_logger
from .skill_scan_api import router as skill_router
from .scan_api import router as scan_router
from .ai_sec_api import router as ai_sec_router
from .digpool_api import router as digpool_router

log = get_logger("web.api")


def create_app() -> FastAPI:
    """创建鉴微平台 API 应用。"""
    app = FastAPI(
        title="鉴微 JianWei AI 安全测试平台",
        description="由玄鉴引擎驱动的 AI 安全测试平台 API（扫描 / 评测 / 护栏 / 报告）",
        version="0.1.0",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"], allow_credentials=True,
        allow_methods=["*"], allow_headers=["*"],
    )

    @app.get("/health")
    async def health():
        return {"status": "ok", "service": "jianwei-api"}

    app.include_router(skill_router)
    app.include_router(scan_router)
    app.include_router(ai_sec_router)
    app.include_router(digpool_router)

    # §13 平台 UI：挂载静态前端（web/static）
    _here = os.path.dirname(os.path.abspath(__file__))
    _static = os.path.join(os.path.dirname(_here), "static")
    if os.path.isdir(_static):
        app.mount("/static", StaticFiles(directory=_static), name="static")

        @app.get("/")
        async def index():
            return FileResponse(os.path.join(_static, "index.html"))

    return app


app = create_app()

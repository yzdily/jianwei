"""鉴微 Web API 应用工厂。"""
from __future__ import annotations

import os
import sys
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from core.log import get_logger
from .skill_scan_api import router as skill_router
from .scan_api import router as scan_router
from .ai_sec_api import router as ai_sec_router
from .digpool_api import router as digpool_router
from .rbac_api import router as rbac_router

log = get_logger("web.api")

# 控制台「系统设置 / 版本信息」需要的运行态开关。
# 只上报「是否已配置」，绝不回传值本身——避免界面变成凭据泄漏面。
_ENV_FLAGS = {
    "auth_enabled": "JIANWEI_API_KEY",
    "llm_key_present": "DIGPOOL_LLM_API_KEY",
}


def _count_operations(app: FastAPI) -> int:
    """统计已注册的 API 操作数。

    注意：FastAPI ≥0.11x 把 `include_router` 收成单个 `_IncludedRouter` 节点，
    直接遍历 `app.routes` 会漏掉全部子路由（实测只数到 7），因此以 OpenAPI 为准
    （schema 生成后会被缓存，重复调用无额外开销）。

    Args:
        app: FastAPI 应用实例。

    Returns:
        各路径下 method 数量之和；schema 生成失败时回退为顶层路由数。
    """
    try:
        paths = app.openapi().get("paths", {})
        return sum(len(methods) for methods in paths.values())
    except Exception:  # noqa: BLE001 - 计数不应影响接口可用性
        return len([r for r in app.routes if getattr(r, "methods", None)])


def _collect_platform_info(app: FastAPI) -> dict[str, Any]:
    """汇总脱敏运行态事实，供统一控制台展示。

    Args:
        app: FastAPI 应用实例（用于读取标题、版本与已注册路由数）。

    Returns:
        含 title / version / routes / python 及 _ENV_FLAGS 各项布尔值的字典。

    Note:
        所有 *_present / *_enabled 字段均为布尔值，不含任何密钥内容。
    """
    info: dict[str, Any] = {
        "title": app.title,
        "version": app.version,
        "routes": _count_operations(app),
        "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
    }
    for key, env_name in _ENV_FLAGS.items():
        info[key] = bool(os.getenv(env_name))
    return info


def create_app() -> FastAPI:
    """创建鉴微平台 API 应用（**单一入口**：控制台与全部 API 同一个 app）。

    说明：`web/api/skill_upload.py` 曾自带 `_build_app()` 与独立 `/` 向导页，
    与主应用构成双入口，已于 2026-10-09 收敛为兼容壳。
    """
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

    @app.get("/api/platform/info", tags=["platform"])
    async def platform_info():
        """返回控制台所需的脱敏运行态信息（密钥仅以布尔存在性呈现）。"""
        return _collect_platform_info(app)

    app.include_router(skill_router)
    app.include_router(scan_router)
    app.include_router(ai_sec_router)
    app.include_router(digpool_router)
    app.include_router(rbac_router)

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

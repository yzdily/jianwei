"""Web API 共用依赖。

收敛前的问题：`skill_scan_api._require_auth` 是**空壳**（只 pass），
`ai_sec_api._require_auth` 才是真校验 —— 同一平台两套鉴权，容易漏保护。
现统一到本模块，所有写接口共用同一实现。
"""
from __future__ import annotations

import os

from fastapi import Header, HTTPException, status

from core.log import get_logger

log = get_logger("web.api.deps")


def require_api_key(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> bool:
    """校验调用方 API Key（设计 §4.2 会话鉴权）。

    Args:
        x_api_key: 请求头 `X-API-Key` 的值。

    Returns:
        True 表示放行。

    Raises:
        HTTPException: 401，当已配置 `JIANWEI_API_KEY` 而请求未携带或值不匹配。

    Note:
        未设置 `JIANWEI_API_KEY` 时视为本地开发模式，放行全部请求（便于零密钥演示）。
    """
    expected = os.getenv("JIANWEI_API_KEY")
    if not expected:
        return True  # 开发模式：未启用鉴权
    if x_api_key and x_api_key == expected:
        return True
    log.warning("auth rejected: missing/invalid X-API-Key")
    raise HTTPException(
        status.HTTP_401_UNAUTHORIZED,
        "Missing or invalid X-API-Key header",
    )

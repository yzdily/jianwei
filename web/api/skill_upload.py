"""兼容壳（Deprecated）—— 上传路由已收敛至 `web/api/skill_scan_api.py`。

历史问题（2026-10-09 收敛前）：
    本模块曾是一个**独立 FastAPI 应用**（`_build_app()`，
    `python -m web.api.skill_upload` 监听 8099），自带 `/` 向导页与一套上传实现，
    与主应用形成「双入口 + 双实现」，返回体还不一致（`done/200` vs `completed/202`）。

现在的边界：
    - 路由唯一实现 → `web/api/skill_scan_api.py`
    - 业务/护栏唯一实现 → `core.llm_security.skill_scan.upload.handle_upload`
    - 界面唯一入口 → 统一控制台（`python start.py --serve` 的 02 上传 Skill 视图）

本文件仅为兼容既有 import 而保留，**不要再往里加路由**。
"""
from __future__ import annotations

# 兼容 re-export：外部若仍 `from web.api.skill_upload import router` 不会崩
from .skill_scan_api import router  # noqa: F401
from core.llm_security.skill_scan.upload import (  # noqa: F401
    handle_upload,
    store_clear,
    store_get,
)

__all__ = ["router", "handle_upload", "store_get", "store_clear"]

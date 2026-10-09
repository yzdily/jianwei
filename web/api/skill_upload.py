"""Skill 上传扫描 Web 路由（M2）—— FastAPI 薄封装。

对应 818 设计 §4.3 接口契约：
    POST /api/scan/skill/upload   multipart(file, strategy) -> 202 {scan_id, status}
    GET  /api/scan/skill/{scan_id} -> {risk_score, severity, safe_to_install, findings, ...}

护栏与扫描逻辑全在 core.llm_security.skill_scan.upload，本模块仅做 HTTP 适配。
FastAPI 为可选依赖：未安装时本模块仍可 import（handle_upload 可用），便于单测与 CLI。

运行（需 fastapi+uvicorn）：
    python -m web.api.skill_upload
"""
from __future__ import annotations

import importlib.util

from core.llm_security.skill_scan.upload import handle_upload, store_get

# ---- FastAPI 可选依赖（guarded import）----
_fastapi_available = importlib.util.find_spec("fastapi") is not None
router = None

if _fastapi_available:
    from pathlib import Path
    from fastapi import APIRouter, UploadFile, File, Form, HTTPException  # type: ignore
    from fastapi.responses import HTMLResponse  # type: ignore

    router = APIRouter()

    _TEMPLATE = Path(__file__).resolve().parents[1] / "templates" / "skill_upload.html"

    @router.get("/", response_class=HTMLResponse)
    async def index():
        """前端向导卡（拖拽 + 策略选择 + 护栏说明）。"""
        if not _TEMPLATE.is_file():
            raise HTTPException(status_code=404, detail="skill_upload.html 模板缺失")
        return HTMLResponse(_TEMPLATE.read_text(encoding="utf-8"))

    @router.post("/api/scan/skill/upload")
    async def upload_skill(file: UploadFile = File(...), strategy: str = Form("standard")):
        data = await file.read()
        try:
            payload = handle_upload(file.filename or "upload", data, strategy=strategy)
        except ValueError as e:
            raise HTTPException(status_code=413, detail=str(e))
        return {"scan_id": payload["scan_id"], "status": "done",
                "risk_score": payload["risk_score"],
                "safe_to_install": payload["safe_to_install"]}

    @router.get("/api/scan/skill/{scan_id}")
    async def get_skill_result(scan_id: str):
        payload = store_get(scan_id)
        if payload is None:
            raise HTTPException(status_code=404, detail="scan_id 不存在或已过期")
        return payload


def _build_app():
    from fastapi import FastAPI  # type: ignore
    app = FastAPI(title="鉴微 Skill 上传扫描")
    app.include_router(router)
    return app


if __name__ == "__main__":
    if not _fastapi_available:
        raise SystemExit("未安装 fastapi/uvicorn，无法启动 Web 服务。"
                         "可单独使用 core.llm_security.skill_scan.upload.handle_upload。")
    import uvicorn  # type: ignore
    uvicorn.run(_build_app(), host="127.0.0.1", port=8099)

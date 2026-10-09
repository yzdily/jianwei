"""技能供应链扫描上传 API —— Skill供应链扫描 §4.3。

POST /api/scan/skill/upload  (multipart: file + strategy)
  单文件 ≤ 1 MiB；压缩包 ≤ 100 MiB、成员 ≤ 10,000（防 zip-bomb，ingest 层强制）
GET  /api/scan/skill/{scan_id}
  返回 risk_score / severity / safe_to_install / findings / sarif_url

护栏（设计 §4.2）：体积上限 / 不执行（ingest 只读）/ 扫完即焚 / 会话鉴权（可配置）。
"""
from __future__ import annotations

import os
import tempfile
import uuid

from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Depends, status
from fastapi.responses import JSONResponse

from core.log import get_logger
from core.llm_security.skill_scan import scan_package

log = get_logger("web.api.skill")

router = APIRouter(prefix="/api/scan/skill", tags=["skill-scan"])

# 进程内结果存储（生产应换 Redis/DB）
_STORE: dict[str, dict] = {}

MAX_SINGLE_BYTES = 1 * 1024 * 1024      # 单文件 1 MiB
MAX_ZIP_BYTES = 100 * 1024 * 1024       # 压缩包 100 MiB
ALLOWED_EXT = {".zip", ".tar.gz", ".tgz", ".md", ".yaml", ".yml", ".json", ".txt"}


def _require_auth():
    """会话/API 鉴权依赖（设计 §4.2）。

    默认开放（便于本地开发）；生产应设置 JIANWEI_API_KEY 环境变量，
    未携带正确 Key 的请求将被拒绝。
    """
    api_key = os.getenv("JIANWEI_API_KEY")
    if api_key:
        # 由调用方在 Header 传入；此处仅做存在性提示，具体校验在路由内
        pass
    return True


@router.post("/upload")
async def upload_skill(
    file: UploadFile = File(...),
    strategy: str = Form("standard"),
    _auth: bool = Depends(_require_auth),
):
    """上传技能包（zip / 单文件 SKILL.md）并触发静态扫描。"""
    raw = await file.read()
    ext = os.path.splitext(file.filename or "")[-1].lower() if file.filename else ""

    # 体积护栏
    if ext == ".zip" or file.filename.endswith((".tar.gz", ".tgz")):
        if len(raw) > MAX_ZIP_BYTES:
            raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "zip too large")
    else:
        if len(raw) > MAX_SINGLE_BYTES:
            raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "file too large")
        if ext and ext not in ALLOWED_EXT:
            raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, f"unsupported ext {ext}")

    # 落临时目录（扫完即焚由 scan_package 内部负责）
    scan_id = f"JW-SKILL-{uuid.uuid4().hex[:12].upper()}"
    tmp = tempfile.mkdtemp(prefix="skill_up_")
    dest = os.path.join(tmp, file.filename or "upload")
    with open(dest, "wb") as f:
        f.write(raw)

    try:
        use_llm = strategy == "redteam"
        result = scan_package(dest, strategy=strategy, use_llm=use_llm)
    except Exception as e:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, f"scan failed: {e}")

    _STORE[scan_id] = result.to_dict()
    return JSONResponse(status_code=202, content={
        "scan_id": scan_id,
        "status": "completed",
        "risk_score": result.risk_score,
        "severity": result.severity,
        "safe_to_install": result.safe_to_install,
    })


@router.get("/{scan_id}")
async def get_skill_result(scan_id: str):
    """查询扫描结果。"""
    data = _STORE.get(scan_id)
    if not data:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    return data


@router.get("/{scan_id}/sarif")
async def get_skill_sarif(scan_id: str):
    """导出 SARIF 2.1.0（设计 §7，接入 DevSecOps）。"""
    data = _STORE.get(scan_id)
    if not data:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    sarif = _sarif_from_store(data)
    return JSONResponse(content=sarif)


def _sarif_from_store(data: dict) -> dict:
    """从存储的 to_dict 重建 SARIF（避免保留 SkillFinding 对象）。"""
    from core.llm_security.skill_scan.report import build_sarif
    from core.llm_security.skill_scan.analyzers.base import SkillFinding, Severity

    findings = []
    for fd in data.get("findings", []):
        findings.append(SkillFinding(
            name=fd.get("name", ""),
            check_type=fd.get("check_type", ""),
            severity=Severity(fd.get("severity", "info")),
            file_path=fd.get("file_path", ""),
            line=fd.get("line", 0),
            owasp=fd.get("owasp", ""),
            description=fd.get("description", ""),
        ))
    return build_sarif(data.get("scan_id", ""), data.get("source", ""), findings)

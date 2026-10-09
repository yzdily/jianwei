"""技能供应链扫描上传 API —— Skill 供应链扫描 §4.3（**唯一实现**）。

契约：
    POST /api/scan/skill/upload   multipart(file + strategy) -> 202
         {scan_id, status, risk_score, severity, safe_to_install}
    GET  /api/scan/skill/{scan_id}        -> 完整结果（findings / 风险分 / 退出码）
    GET  /api/scan/skill/{scan_id}/sarif  -> SARIF 2.1.0（接入 DevSecOps 门禁）

收敛说明（2026-10-09）：
    本端点此前存在**两套实现**——本模块（扩展名白名单 + 自建临时目录）与
    `web/api/skill_upload.py`（二进制预筛 + 沙箱扫完即焚），返回体还不一致
    （`completed/202` vs `done/200`）。现统一以
    `core.llm_security.skill_scan.upload.handle_upload` 为唯一业务实现
    （护栏更全：策略校验 / 体积上限 / 二进制预筛 / 扫完即焚），
    HTTP 层只做协议适配；`skill_upload.py` 退化为兼容壳。

护栏（设计 §4.2）：
    - 体积上限：单文件 ≤ 1 MiB、压缩包 ≤ 100 MiB（core 强制，超限 ValueError → 413）
    - 不执行被扫对象：ingest 只读解包
    - 扫完即焚：上传沙箱在 core 层 finally 清理
    - 会话鉴权：`JIANWEI_API_KEY`（见 web/api/deps.py）
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from fastapi.responses import JSONResponse

from core.llm_security.skill_scan.upload import handle_upload, store_get
from core.log import get_logger

from .deps import require_api_key

log = get_logger("web.api.skill")

router = APIRouter(prefix="/api/scan/skill", tags=["skill-scan"])


@router.post("/upload", status_code=status.HTTP_202_ACCEPTED)
async def upload_skill(
    file: UploadFile = File(...),
    strategy: str = Form("standard"),
    _auth: bool = Depends(require_api_key),
):
    """上传技能包（zip / 单文件 SKILL.md）并触发静态扫描。

    Args:
        file: 上传文件（zip / tar.gz / 单文件）。
        strategy: passive / standard / redteam / compliance。
        _auth: 鉴权依赖（未配置 JIANWEI_API_KEY 时放行）。

    Returns:
        202 + {scan_id, status, risk_score, severity, safe_to_install}。

    Raises:
        HTTPException: 413 体积超限；422 策略非法；500 扫描异常。
    """
    raw = await file.read()

    try:
        payload = handle_upload(file.filename or "upload", raw, strategy=strategy)
    except ValueError as e:
        # handle_upload 的 ValueError 只有两类：体积超限 / 策略非法
        detail = str(e)
        code = (
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
            if "超限" in detail
            else status.HTTP_422_UNPROCESSABLE_ENTITY
        )
        raise HTTPException(code, detail) from e
    except Exception as e:  # noqa: BLE001 - 兜底 500，避免内部细节直接外泄
        log.error(f"skill upload failed: {e}")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, f"scan failed: {e}") from e

    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED,
        content={
            "scan_id": payload["scan_id"],
            "status": "completed",
            "risk_score": payload["risk_score"],
            "severity": payload["severity"],
            "safe_to_install": payload["safe_to_install"],
        },
    )


@router.get("/{scan_id}")
async def get_skill_result(scan_id: str):
    """查询扫描结果（完整 findings 与评分）。"""
    data = store_get(scan_id)
    if not data:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    return data


@router.get("/{scan_id}/sarif")
async def get_skill_sarif(scan_id: str, _auth: bool = Depends(require_api_key)):
    """导出 SARIF 2.1.0（设计 §7，接入 DevSecOps）。"""
    data = store_get(scan_id)
    if not data:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    return JSONResponse(content=_sarif_from_store(data))


def _sarif_from_store(data: dict) -> dict:
    """从存储的 to_dict 结果重建 SARIF（避免保留 SkillFinding 对象）。"""
    from core.llm_security.skill_scan.analyzers.base import Severity, SkillFinding
    from core.llm_security.skill_scan.report import build_sarif

    findings = [
        SkillFinding(
            name=fd.get("name", ""),
            check_type=fd.get("check_type", ""),
            severity=Severity(fd.get("severity", "info")),
            file_path=fd.get("file_path", ""),
            line=fd.get("line", 0),
            owasp=fd.get("owasp", ""),
            description=fd.get("description", ""),
        )
        for fd in data.get("findings", [])
    ]
    return build_sarif(data.get("scan_id", ""), data.get("source", ""), findings)

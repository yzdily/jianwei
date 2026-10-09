"""通用扫描 API —— 双轴扫描入口（MASTER_PLAN §12）。

POST /api/scan/target
  body: { url, target_type, strategy, headers?, extra? }
  → 经 core.fast_scanner.FastScanner 分发（get_scan_strategy 组装规则）
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from core.log import get_logger
from core.fast_scanner import FastScanner, ScanTarget

from .auth import RequireAuth

log = get_logger("web.api.scan")

router = APIRouter(prefix="/api/scan", tags=["scan"])


class ScanRequest(BaseModel):
    url: str = Field(default="", description="目标 URL（skill 类型可留空，改用 skill_path）")
    target_type: str = Field(default="web", description="web/api/llm_app/agent/rag/skill")
    strategy: str = Field(default="standard", description="passive/standard/redteam/compliance")
    headers: dict = Field(default_factory=dict)
    extra: dict = Field(default_factory=dict)
    skill_path: str = Field(default="", description="skill 类型的本地包路径")


class ScanResponse(BaseModel):
    target_type: str
    strategy: str
    enabled_rules: list[str]
    findings_count: int
    findings: list[dict]


@router.post("/target", response_model=ScanResponse)
async def scan_target(req: ScanRequest, _auth: bool = Depends(RequireAuth("scan.run"))):
    """对目标执行双轴扫描。"""
    target = ScanTarget(
        url=req.url,
        headers=req.headers,
        extra=req.extra,
        target_type=req.target_type,
    )
    if req.target_type == "skill" and req.skill_path:
        target.extra.setdefault("skill", {})["path"] = req.skill_path

    try:
        scanner = FastScanner()
        findings = await scanner.scan_target(target, strategy=req.strategy, target_type=req.target_type)
    except Exception as e:
        log.error(f"scan_target failed: {e}")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, f"scan failed: {e}")

    return ScanResponse(
        target_type=req.target_type,
        strategy=req.strategy,
        enabled_rules=scanner._scan_config.enabled_rules if scanner._scan_config else [],
        findings_count=len(findings),
        findings=[f.to_dict() for f in findings],
    )

"""鉴微 JianWei AI 安全平台 API —— L4 度量 / L5 报告（MASTER_PLAN PD7）。

端点（统一前缀 /api/ai-sec）：
  POST /report/scan           对目标跑双轴扫描并直接生成 OWASP LLM Top 10 报告
  POST /report/from-findings  用调用方已有的 findings 列表生成报告（解耦复用）
  GET  /report/{scan_id}      取已生成报告的 markdown
  GET  /report/{scan_id}/sarif 取报告的 SARIF 2.1.0 导出
  POST /metrics/summary       聚合多次扫描结果，返回 ASR/拒答率/泄露率/护栏拦截率
  GET  /benchmark/summary      返回 Golden 基线评测摘要（tests/golden 回放口径）

设计依据：818/AI安全测试平台_MASTER_PLAN.md §11.4（L4 度量）/ §11.5（L5 报告）。
护栏：生产可设 JIANWEI_API_KEY；默认开放便于本地开发。
"""
from __future__ import annotations

import os
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

from core.ai_sec.metrics.calculator import MetricsCalculator
from core.ai_sec.models import AIRiskFinding
from core.ai_sec.report import (
    build_llm_top10_sarif,
    build_report,
)
from core.fast_scanner import FastScanner, ScanTarget
from core.log import get_logger
from .deps import require_api_key as _require_auth
from .report_store import store

log = get_logger("web.api.ai_sec")

router = APIRouter(prefix="/api/ai-sec", tags=["ai-sec-report"])


# ----------------------------------------------------------------------------
# 请求 / 响应模型
# ----------------------------------------------------------------------------
class FindingInput(BaseModel):
    """单条 AI 风险发现（与 core.ai_sec.models.AIRiskFinding 对齐）。"""
    owasp: str = Field(..., description="OWASP 类别，如 LLM01 / RAG / AGENT / MCP")
    vuln_type: str = Field(..., description="具体漏洞类型，如 llm_prompt_injection")
    severity: str = Field(..., description="critical/high/medium/low/info")
    url: str = Field(default="", description="命中位置 URL")
    detail: str = Field(default="", description="发现描述")
    evidence: str = Field(default="")
    payload: str = Field(default="")
    fix_suggestion: str = Field(default="")
    confidence: float = Field(default=0.0)
    evidence_quality: str = Field(default="")
    trace_id: str = Field(default="")
    rule_tag: str = Field(default="")


class ReportFromFindingsRequest(BaseModel):
    target_url: str = Field(default="mock://llm", description="报告目标标识")
    findings: list[FindingInput]
    scan_id: str = Field(default="", description="可选自定义 scan_id；留空自动生成")
    benchmark_per_class: dict | None = Field(default=None, description="可选：golden 基准 per-class 表")


class ReportScanRequest(BaseModel):
    url: str = Field(default="", description="目标 URL（skill 类型可留空，改用 skill_path）")
    target_type: str = Field(default="llm_app", description="web/api/llm_app/agent/rag/skill")
    strategy: str = Field(default="standard", description="passive/standard/redteam/compliance")
    headers: dict = Field(default_factory=dict)
    extra: dict = Field(default_factory=dict)
    skill_path: str = Field(default="", description="skill 类型的本地包路径")
    scan_id: str = Field(default="", description="可选自定义 scan_id；留空自动生成")


class MetricRecordInput(BaseModel):
    """单次扫描/红队结果记录（喂给 MetricsCalculator）。"""
    total: int = Field(..., ge=0, description="攻击总数")
    success: int = Field(default=0, ge=0, description="成功次数（ASR 分子）")
    refusals: int = Field(default=0, ge=0, description="拒答次数")
    leaks: int = Field(default=0, ge=0, description="泄露次数")
    shield_blocked: int = Field(default=0, ge=0, description="护栏拦截次数")
    shield_total: int = Field(default=0, ge=0, description="护栏总次数")


# ----------------------------------------------------------------------------
# 鉴权依赖：统一由 web/api/deps.py 提供
# （此前本模块与 skill_scan_api 各持一份，且后者是空壳 —— 同一平台两套鉴权，已收敛）
# ----------------------------------------------------------------------------


def _to_finding(d: FindingInput) -> AIRiskFinding:
    return AIRiskFinding(
        owasp=d.owasp,
        vuln_type=d.vuln_type,
        severity=d.severity,
        url=d.url,
        detail=d.detail,
        evidence=d.evidence,
        payload=d.payload,
        fix_suggestion=d.fix_suggestion,
        confidence=d.confidence,
        evidence_quality=d.evidence_quality,
        trace_id=d.trace_id,
        rule_tag=d.rule_tag,
    )


# ----------------------------------------------------------------------------
# 端点
# ----------------------------------------------------------------------------
@router.post("/report/scan")
async def report_scan(req: ReportScanRequest, _auth: bool = Depends(_require_auth)):
    """对目标执行双轴扫描，并直接生成 OWASP LLM Top 10 报告（markdown + SARIF）。"""
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
        log.error(f"report_scan failed: {e}")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, f"scan failed: {e}")

    scan_id = req.scan_id or f"JW-RPT-{uuid.uuid4().hex[:12].upper()}"
    markdown = build_report(req.url or target.target_type, findings, scan_id=scan_id)
    sarif = build_llm_top10_sarif(scan_id, findings)

    store.put(scan_id, {
        "scan_id": scan_id,
        "target_url": req.url or target.target_type,
        "target_type": req.target_type,
        "strategy": req.strategy,
        "findings_count": len(findings),
        "markdown": markdown,
        "sarif": sarif,
    })
    return {
        "scan_id": scan_id,
        "target_type": req.target_type,
        "strategy": req.strategy,
        "findings_count": len(findings),
        "report_markdown": markdown,
    }


@router.post("/report/from-findings")
async def report_from_findings(req: ReportFromFindingsRequest, _auth: bool = Depends(_require_auth)):
    """用调用方已有的 findings 列表生成 OWASP LLM Top 10 报告（解耦复用）。

    适用于：已通过 skill 供应链扫描 / 外部红队 / 历史结果得到 findings，
    想直接产出统一格式报告的场景。
    """
    if not req.findings:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "findings must not be empty")
    try:
        findings = [_to_finding(f) for f in req.findings]
    except Exception as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"invalid finding: {e}")

    scan_id = req.scan_id or f"JW-RPT-{uuid.uuid4().hex[:12].upper()}"
    markdown = build_report(req.target_url, findings, scan_id=scan_id, benchmark_per_class=req.benchmark_per_class)
    sarif = build_llm_top10_sarif(scan_id, findings)

    store.put(scan_id, {
        "scan_id": scan_id,
        "target_url": req.target_url,
        "target_type": "findings",
        "strategy": "-",
        "findings_count": len(findings),
        "markdown": markdown,
        "sarif": sarif,
    })
    return {
        "scan_id": scan_id,
        "target_url": req.target_url,
        "findings_count": len(findings),
        "report_markdown": markdown,
    }


@router.get("/report/{scan_id}")
async def get_report(scan_id: str, _auth: bool = Depends(_require_auth)):
    """取已生成报告的 markdown。"""
    data = store.get(scan_id)
    if not data:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "report not found")
    return PlainTextResponse(data["markdown"], media_type="text/markdown; charset=utf-8")


@router.get("/report/{scan_id}/sarif")
async def get_report_sarif(scan_id: str, _auth: bool = Depends(_require_auth)):
    """取报告的 SARIF 2.1.0 导出（接入 DevSecOps / CI 门禁）。"""
    data = store.get(scan_id)
    if not data:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "report not found")
    return JSONResponse(content=data["sarif"])


@router.post("/metrics/summary")
async def metrics_summary(records: list[MetricRecordInput], _auth: bool = Depends(_require_auth)):
    """聚合多次扫描/红队结果，返回 L4 度量汇总（ASR/拒答率/泄露率/护栏拦截率）。"""
    if not records:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "records must not be empty")
    calc = MetricsCalculator()
    for r in records:
        calc.add_result(
            total=r.total, success=r.success, refusals=r.refusals,
            leaks=r.leaks, shield_blocked=r.shield_blocked, shield_total=r.shield_total,
        )
    return calc.calculate().to_dict()


# ----------------------------------------------------------------------------
# 基准评测摘要（Golden 基线口径）
# ----------------------------------------------------------------------------

_GOLDEN = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "tests", "golden", "llmvault_benchmark.jsonl",
)


@router.get("/benchmark/summary")
async def benchmark_summary(_auth: bool = Depends(_require_auth)):
    """返回 Golden 基线评测摘要（tests/golden/llmvault_benchmark.jsonl 回放）。

    注：这是基线口径（验证「规则→探针→judge→命中」管线自洽），
    非 live LLMVault 真实检测率；live 实测见 scripts/run_live_benchmark.py。
    """
    from core.llm_security.benchmark import run_benchmark_from_file

    if not os.path.exists(_GOLDEN):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "golden baseline not found")
    report = await run_benchmark_from_file(_GOLDEN)
    return report.to_dict()

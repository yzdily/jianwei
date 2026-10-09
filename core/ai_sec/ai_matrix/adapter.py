"""AIRiskFinding → 矩阵 finding 适配器（纯字段平移，无新判定）。

把平台 L2 的 `AIRiskFinding` 映射为引擎矩阵门（GATE-TRI）所需的字段
（见设计稿 §3.6 溯源证据契约）。绝不在此做「是否漏洞」的判断——交门与裁决。

注意：平台 `AIRiskFinding.confidence` 是 0–1 浮点，而引擎门 `build_verdict` 读的是
**置信度标签**（confirmed/observed/inferred）；适配器负责换算，避免口径错配。
"""
from __future__ import annotations

from typing import Any

__all__ = ["to_matrix_finding"]


def _conf_label(confidence: Any) -> str:
    """0–1 浮点 → 引擎置信度标签（confirmed/observed/inferred）。"""
    try:
        c = float(confidence)
    except (TypeError, ValueError):
        return "inferred"
    if c >= 0.8:
        return "confirmed"
    if c >= 0.5:
        return "observed"
    return "inferred"


def to_matrix_finding(finding: Any, *, domain: str = "ai") -> dict:
    """把 AIRiskFinding（或其 to_dict()）平移为矩阵门可消费的 finding dict。"""
    d = finding.to_dict() if hasattr(finding, "to_dict") else dict(finding)

    evidence_response = d.get("response_snippet") or d.get("evidence") or ""
    return {
        "target": d.get("url", ""),
        "vuln_class": d.get("vuln_type", ""),
        "domain": domain,
        "owasp": d.get("owasp", ""),
        "severity": d.get("severity", ""),
        "confidence": _conf_label(d.get("confidence", 0.0)),
        "confidence_score": d.get("confidence", 0.0),
        "detail": d.get("detail", ""),
        # 溯源证据（GATE-TRI 必需）
        "evidence_request": d.get("payload", ""),
        "evidence_response": evidence_response,
        "trace_id": d.get("trace_id", ""),
        "evidence_quality": d.get("evidence_quality", ""),
        "fix_suggestion": d.get("fix_suggestion", ""),
        # 供本地回退门判定（has_data）
        "data": evidence_response,
        "identities": d.get("identities", []),
    }

"""AIMatrixRunner 的门与裁决 —— 优先复用引擎，缺失时本地等价降级。

设计（《AI风险接入testflow矩阵_设计稿》§3.5）：AI finding 与 Web finding 走**同一套**门，
禁止平台自建第二套判定。因此本模块优先 `import` 引擎的 `core.testflow.gates` + `core.verdict`
（纯函数）；当引擎未安装（零依赖环境）时，用**等价语义**的本地回退，保证可跑。
"""
from __future__ import annotations

from typing import Any

# ── 优先复用引擎（持续维护的 xuanjian 引擎）─────────────────────────────
_ENGINE = False
try:  # pragma: no cover - 依赖引擎是否安装
    from core.testflow.gates import gate_pre as _engine_gate_pre  # type: ignore
    from core.testflow.gates import run_triage_gate as _engine_triage  # type: ignore

    _ENGINE = True
except Exception:  # pragma: no cover - 零依赖回退
    _engine_gate_pre = None
    _engine_triage = None

DENY_STATUS = (401, 403, 500)
_TRIAGE_ADMISSIBLE = ("high", "critical")
_CONFIDENCES = ("confirmed", "observed", "inferred")


# ── 本地等价回退（语义对齐引擎 core/verdict.py 三道门）──────────────────
def _local_gate_pre(step: dict) -> tuple[bool, str]:
    for fld in ("id", "executor"):
        if not step.get(fld):
            return False, f"step 缺 {fld}"
    if step["executor"] not in ("local", "llm", "tool"):
        return False, f"未知 executor: {step['executor']}"
    if step["executor"] == "tool" and not step.get("tool"):
        return False, "tool 步骤缺 tool 引用"
    return True, ""


def _local_build_verdict(f: dict, baseline: dict | None = None) -> dict:
    status = f.get("http_code") or f.get("status") or 0
    try:
        status = int(status)
    except (TypeError, ValueError):
        status = 0
    evidence = f.get("evidence_response") or f.get("response") or f.get("evidence") or ""
    body = f.get("data") or f.get("response_body") or evidence
    ok_code = status not in DENY_STATUS
    ok_data = bool(body) and body not in ("", [], {})
    ok_ctrl = True
    if baseline is not None:
        try:
            base_status = int(baseline.get("http_code") or baseline.get("status") or 0)
        except (TypeError, ValueError):
            base_status = 0
        ok_ctrl = base_status in DENY_STATUS
    if ok_code and ok_data and ok_ctrl:
        verdict = "vulnerable"
    elif not ok_code:
        verdict = "safe"
    else:
        verdict = "needs_follow_up"
    return {
        "business_code": f.get("business_code"),
        "has_data": ok_data,
        "identities": list(f.get("identities") or []),
        "deep_dive_level": int(f.get("deep_dive_level") or 0),
        "confidence": f.get("confidence") if f.get("confidence") in _CONFIDENCES else "inferred",
        "verdict": verdict,
    }


def _local_triage(findings: list[dict], *, baseline: dict | None = None) -> tuple[list, list]:
    admitted, blocked = [], []
    for f in findings:
        v = _local_build_verdict(f, baseline)
        f["verdict"] = v
        has_evidence = bool(f.get("evidence_request") or f.get("evidence")) and bool(
            f.get("evidence_response") or f.get("response") or f.get("data")
        )
        if not has_evidence:
            f["_triage_blocked"] = True
            f["_triage_reason"] = "缺 evidence_request/response 溯源"
            blocked.append(f)
            continue
        sev = str(f.get("severity") or "").lower()
        if sev in _TRIAGE_ADMISSIBLE:
            if v["verdict"] != "vulnerable":
                f["_fp_downgraded"] = True
                f["severity"] = "info"
                f["_triage_reason"] = f"verdict={v['verdict']}（门未全过）"
            elif v["confidence"] not in _CONFIDENCES:
                f["_fp_downgraded"] = True
                f["severity"] = "info"
                f["_triage_reason"] = f"confidence 非法: {v['confidence']}"
        admitted.append(f)
    return admitted, blocked


# ── 统一出口（引擎优先，回退兜底）──────────────────────────────────────
def uses_engine() -> bool:
    return _ENGINE


def gate_pre(step: dict) -> tuple[bool, str]:
    return _engine_gate_pre(step) if _ENGINE else _local_gate_pre(step)


def run_triage_gate(findings: list[dict], *, baseline: dict | None = None) -> tuple[list, list]:
    if _ENGINE:
        try:
            return _engine_triage(findings, baseline=baseline)
        except Exception:  # pragma: no cover - 引擎异常时回退
            pass
    return _local_triage(findings, baseline=baseline)

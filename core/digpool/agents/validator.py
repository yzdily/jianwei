"""M3 · Validator —— 双重去误报，把 LOOP 合成 Finding 升级为「已验证漏洞」。

对齐《鉴微优化方案 §5》M3 / TechPlan「VERIFY 双重去误报，仅确定性漏洞进入报告」：
- **门 1 证据门**：必须携带可复现证据（payload/响应/snippet/命中行/观测产物），
  否则最多算「疑似」，不进入已确认清单；
- **门 2 佐证门**：必须有具体命中位置（url/file_path），且同类型+同目标不得重复。

判定三态：`confirmed`（双门通过）/ `suspect`（证据不足）/ `rejected`（无位置或重复）。

设计纪律：
- 优先接引擎 `harm_validation`；**引擎缺失时降级 `StubValidator`**（零依赖可跑）。
- 只消费 Finding 的公开字段（id/vuln_type/severity/url/detail/extracted_artifacts），不碰引擎内部类。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Optional

from core.digpool.loops.loop_controller import Finding
from core.log import get_logger

log = get_logger("core.digpool.agents.validator")

VERDICT_CONFIRMED = "confirmed"
VERDICT_SUSPECT = "suspect"
VERDICT_REJECTED = "rejected"

# 视为「可复现证据」的字段名（出现在 detail / extracted_artifacts 即算命中）
_EVIDENCE_KEYS = frozenset({
    "payload", "response", "evidence", "proof", "trace_id", "status_code",
    "http_status", "snippet", "matched", "match", "request", "body", "raw",
    "sample", "observed", "result", "output",
})


def _as_str(v: Any) -> str:
    return "" if v is None else str(v)


def _truthy(v: Any) -> bool:
    return v not in (None, "", [], {}, b"", 0, "0")


def _has_evidence(f: Finding) -> bool:
    """门 1：是否存在可复现证据。"""
    artifacts = getattr(f, "extracted_artifacts", None) or {}
    detail = getattr(f, "detail", None) or {}
    for bucket in (artifacts, detail):
        if not isinstance(bucket, dict):
            continue
        for k, v in bucket.items():
            if k in _EVIDENCE_KEYS and _truthy(v):
                return True
    # 特例：文件 + 行号即视为可定位证据
    if detail.get("file_path") and _truthy(detail.get("line")):
        return True
    return False


def _location(f: Finding) -> str:
    detail = getattr(f, "detail", None) or {}
    return _as_str(getattr(f, "url", "") or detail.get("file_path") or detail.get("asset") or "")


def _base_confidence(f: Finding) -> float:
    detail = getattr(f, "detail", None) or {}
    try:
        return float(detail.get("confidence", 0.6))
    except Exception:
        return 0.6


@dataclass
class ValidationResult:
    """对单条 Finding 的验证结论。"""

    finding: Finding
    verdict: str
    confidence: float
    verified: bool
    reasons: list[str]
    validator: str

    def to_dict(self) -> dict:
        f = self.finding
        return {
            "id": getattr(f, "id", ""),
            "vuln_type": getattr(f, "vuln_type", ""),
            "severity": getattr(f, "severity", ""),
            "location": _location(f),
            "verdict": self.verdict,
            "confidence": round(self.confidence, 3),
            "verified": self.verified,
            "reasons": list(self.reasons),
            "validator": self.validator,
        }


class BaseValidator:
    """验证器基类。"""

    name = "base"

    def validate(self, findings: Iterable[Finding], *, context: Optional[dict] = None) -> list[ValidationResult]:
        raise NotImplementedError

    def confirmed(self, findings: Iterable[Finding], *, context: Optional[dict] = None) -> list[Finding]:
        """只返回双门通过的确定性 Finding。"""
        return [r.finding for r in self.validate(findings, context=context) if r.verified]


class StubValidator(BaseValidator):
    """零依赖验证器：结构门（证据）+ 佐证门（位置/去重）双重去误报。"""

    name = "stub"

    def validate(self, findings: Iterable[Finding], *, context: Optional[dict] = None) -> list[ValidationResult]:
        results: list[ValidationResult] = []
        seen: set[tuple[str, str]] = set()
        for f in findings:
            reasons: list[str] = []
            conf = _base_confidence(f)

            # 门 1：证据门
            if not _has_evidence(f):
                reasons.append("证据门未过：缺少可复现证据（payload/响应/snippet/命中位置）")

            # 门 2：佐证门（位置 + 去重）
            loc = _location(f)
            key = (_as_str(getattr(f, "vuln_type", "")).lower(), loc.lower())
            if not loc:
                reasons.append("佐证门未过：无具体命中位置")
            elif key in seen:
                reasons.append("佐证门未过：同类型同目标重复发现")
            else:
                seen.add(key)

            hard = [r for r in reasons if r.startswith("佐证门未过")]
            if hard:
                verdict, confidence = VERDICT_REJECTED, 0.0
            elif reasons:
                verdict, confidence = VERDICT_SUSPECT, min(conf, 0.4)
            else:
                verdict, confidence = VERDICT_CONFIRMED, max(conf, 0.8)

            results.append(ValidationResult(
                finding=f, verdict=verdict, confidence=confidence,
                verified=(verdict == VERDICT_CONFIRMED),
                reasons=reasons, validator=self.name,
            ))
        return results


class HarmValidator(StubValidator):
    """接引擎 `harm_validation` 的验证器；引擎调用失败时逐条降级到结构门。"""

    name = "harm_validation"

    def __init__(self, engine_fn: Any):
        self._engine = engine_fn

    def validate(self, findings: Iterable[Finding], *, context: Optional[dict] = None) -> list[ValidationResult]:
        results: list[ValidationResult] = []
        for f in findings:
            try:
                verdict = self._engine(f, context or {})
                results.append(self._from_engine(f, verdict))
            except Exception as exc:  # noqa: BLE001 - 引擎单条失败不拖垮整体
                log.warning(f"harm_validation 失败，降级结构门: {exc}")
                results.extend(super().validate([f], context=context))
        return results

    def _from_engine(self, f: Finding, verdict: Any) -> ValidationResult:
        if isinstance(verdict, dict):
            verified = bool(verdict.get("verified") or verdict.get("confirmed"))
            reason = _as_str(verdict.get("reason") or verdict.get("rationale") or "harm_validation 判定")
            conf = float(verdict.get("confidence", 0.9 if verified else 0.3))
        else:
            verified = bool(verdict)
            reason, conf = "harm_validation 判定", (0.9 if verified else 0.3)
        return ValidationResult(
            finding=f,
            verdict=VERDICT_CONFIRMED if verified else VERDICT_REJECTED,
            confidence=conf, verified=verified,
            reasons=[] if verified else [reason],
            validator=self.name,
        )


def _probe_engine_validator() -> Optional[Any]:
    """探测玄鉴 harm_validation 公开入口；缺失返回 None（降级 StubValidator）。"""
    try:
        import xuanjian  # noqa: F401
    except Exception:
        return None
    try:
        from xuanjian.core import harm_validation as hv  # type: ignore
    except Exception:
        return None
    for attr in ("validate_finding", "verify_finding", "validator"):
        fn = getattr(hv, attr, None)
        if callable(fn):
            log.info(f"已链接引擎 harm_validation 入口: harm_validation.{attr}")
            return fn
    return None


def get_validator() -> BaseValidator:
    """优先接引擎 harm_validation，缺失则 StubValidator（零依赖兜底）。"""
    engine = _probe_engine_validator()
    if engine is not None:
        return HarmValidator(engine)
    return StubValidator()


__all__ = [
    "VERDICT_CONFIRMED", "VERDICT_SUSPECT", "VERDICT_REJECTED",
    "ValidationResult", "BaseValidator", "StubValidator", "HarmValidator", "get_validator",
]

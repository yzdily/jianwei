"""共享探针运行器：发射 + 判定 + 归一化为 AIRiskFinding。

供 llm_rag_poison / llm_agent_escape / llm_mcp_exploit 三个新增 check 复用
（LLM扫描器 §1.7）。离线测试通过 responder 注入假响应。

本文件是「命中判定 + finding 构建」的**单一事实源**：
- `run_probe_outcome` → 返回完整 ProbeOutcome（含未命中的置信度/证据），供测试集统计用；
- `run_probe`        → 薄封装，命中返回 AIRiskFinding，否则 None（保持向后兼容）；
- `build_finding`    → 由命中证据构建 AIRiskFinding（供自定义判定器如 RAG 溯源复用）。

平台层 prompt_injection 运行器与引擎级三个 extra check 均复用此处，避免第三份判定逻辑。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from core.ai_sec.models import AIRiskFinding
from core.llm_security.attacks import AttackResult, fire_attack
from core.llm_security.judge import judge_response
from core.llm_security.scoring import make_trace_id

__all__ = ["ProbeOutcome", "run_probe_outcome", "run_probe", "build_finding"]


@dataclass
class ProbeOutcome:
    """单条探针的完整结果（无论是否命中）。测试集需要未命中的统计，故不丢信息。"""

    hit: bool = False
    evidence: str = ""
    confidence: float = 0.0
    response_text: str = ""
    error: str = ""
    finding: AIRiskFinding | None = None


async def run_probe_outcome(
    target: Any, probe: dict, responder: Any | None = None
) -> ProbeOutcome:
    """发射单条探针并判定，返回完整结果。"""
    result: AttackResult = await fire_attack(target, probe, responder=responder)
    hit, evidence, confidence = judge_response(
        probe, result.response_text, result.tool_results
    )
    outcome = ProbeOutcome(
        hit=hit,
        evidence=evidence,
        confidence=confidence,
        response_text=result.response_text,
        error=result.error,
    )
    if hit:
        outcome.finding = build_finding(target, probe, evidence, confidence, result)
    return outcome


async def run_probe(target: Any, probe: dict, responder: Any | None = None) -> AIRiskFinding | None:
    """发射单条探针并判定，命中则返回 AIRiskFinding（向后兼容签名）。"""
    return (await run_probe_outcome(target, probe, responder=responder)).finding


def build_finding(
    target: Any,
    probe: dict,
    evidence: str,
    confidence: float,
    result: AttackResult,
) -> AIRiskFinding:
    """命中 → 统一 AIRiskFinding（L2 全层共用 schema）。"""
    owasp = probe.get("owasp", "")
    check = probe.get("check", "llm_probe")
    return AIRiskFinding(
        owasp=owasp,
        vuln_type=check,
        severity=probe.get("severity", "high"),
        url=getattr(target, "url", ""),
        detail=f"[{owasp}] {probe.get('description', '')}",
        evidence=evidence[:500],
        payload=str(probe.get("turns", ""))[:200],
        fix_suggestion=probe.get("fix", ""),
        confidence=confidence,
        evidence_quality="body_confirmed" if confidence >= 0.8 else "header_only",
        trace_id=make_trace_id(owasp, check),
        rule_tag=f"LLM-{owasp}",
        attack_turns=probe.get("turns", []),
        response_snippet=result.response_text[:300],
    )


# 向后兼容别名
_build_finding = build_finding

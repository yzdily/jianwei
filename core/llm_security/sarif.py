"""通用 SARIF 2.1.0 导出（L2 → L5 报告层衔接）。

把统一 AIRiskFinding 回流（LLM 扫描 / FastScanner 统一扫描）输出为
SARIF 2.1.0 标准 JSON，供 CI / IDE / DevSecOps / 安全编排平台直接消费。

设计对齐：
- 与 skill_scan/report.py::to_sarif 保持同一 SARIF 结构与严重级映射，
  便于平台内多引擎统一输出。
- 全部按鸭子类型 getattr 取值，不硬依赖具体模型类（避免 llm_security
  与 fast_scanner 之间的循环 import）。
"""
from __future__ import annotations

SEV_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "none",
}

DEFAULT_TOOL = {
    "name": "jianwei-ai-scan",
    "version": "2.0",
    "informationUri": "https://github.com/yzdily/xuanjian",
}


def _sev_level(severity: str) -> str:
    return SEV_LEVEL.get((severity or "").lower(), "warning")


def findings_to_sarif(
    findings: list,
    *,
    tool_name: str = DEFAULT_TOOL["name"],
    tool_version: str = DEFAULT_TOOL["version"],
    information_uri: str = DEFAULT_TOOL["informationUri"],
    target: str = "",
    strategy: str = "standard",
    execution_successful: bool = True,
    run_properties: dict | None = None,
) -> dict:
    """把一批 AIRiskFinding 样式对象导出为 SARIF 2.1.0 dict。

    findings 元素需具备（鸭子类型）：owasp / vuln_type / severity / detail，
    可选：evidence / payload / fix_suggestion / confidence / evidence_quality /
    trace_id / url / file_path。
    """
    # ---- 规则去重（保持首次出现顺序）----
    rule_index: dict[str, int] = {}
    rules: list[dict] = []
    for f in findings:
        rid = getattr(f, "vuln_type", "") or "unknown"
        if rid not in rule_index:
            rule_index[rid] = len(rules)
            owasp = getattr(f, "owasp", "")
            rules.append({
                "id": rid,
                "name": rid,
                "shortDescription": {"text": f"{owasp} {rid}".strip()},
                "fullDescription": {"text": getattr(f, "detail", "") or rid},
                "help": {
                    "text": getattr(f, "fix_suggestion", "")
                    or "参见 OWASP LLM Top 10 相关条目。",
                    "markdown": (
                        f"**修复建议**：{getattr(f, 'fix_suggestion', '') or 'N/A'}\n\n"
                        f"**OWASP**：{getattr(f, 'owasp', 'N/A')}"
                    ),
                },
                "properties": {
                    "owasp": getattr(f, "owasp", ""),
                    "severity": getattr(f, "severity", ""),
                },
            })

    # ---- 结果条目 ----
    sarif_results = []
    for f in findings:
        rid = getattr(f, "vuln_type", "") or "unknown"
        detail = getattr(f, "detail", "")
        evidence = str(getattr(f, "evidence", "") or "")[:300]
        msg = detail or rid
        if evidence:
            msg = f"{msg} | 证据: {evidence}"
        loc_uri = getattr(f, "file_path", None) or getattr(f, "url", None) or target
        result = {
            "ruleId": rid,
            "ruleIndex": rule_index.get(rid, 0),
            "level": _sev_level(getattr(f, "severity", "")),
            "message": {"text": msg[:500]},
            "locations": ([{
                "physicalLocation": {
                    "artifactLocation": {"uri": loc_uri},
                }
            }] if loc_uri else []),
            "properties": {
                "owasp": getattr(f, "owasp", ""),
                "severity": getattr(f, "severity", ""),
                "confidence": round(float(getattr(f, "confidence", 0.0) or 0.0), 2),
                "evidenceQuality": getattr(f, "evidence_quality", ""),
                "traceId": getattr(f, "trace_id", ""),
                "payload": str(getattr(f, "payload", "") or "")[:200],
                "fixSuggestion": getattr(f, "fix_suggestion", ""),
            },
        }
        sarif_results.append(result)

    props = {
        "target": target,
        "strategy": strategy,
    }
    if run_properties:
        props.update(run_properties)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": tool_version,
                    "informationUri": information_uri,
                    "rules": rules,
                }
            },
            "invocations": [{
                "executionSuccessful": execution_successful,
                "properties": props,
            }],
            "properties": props,
            "results": sarif_results,
        }],
    }


def llm_result_to_sarif(result, strategy: str = "standard") -> dict:
    """LLM 扫描结果（LLMScanResult 或同构对象）→ SARIF。

    run_properties 带攻击统计与 ASR，便于把 LLM 专项指标带入 CI 看板。
    """
    findings = getattr(result, "findings", []) or []
    total = getattr(result, "total_attacks", 0)
    success = getattr(result, "successful_attacks", 0)
    asr = (success / total) if total else 0.0
    return findings_to_sarif(
        findings,
        tool_name="jianwei-llm-scan",
        tool_version="2.0",
        target=getattr(result, "target_url", ""),
        strategy=strategy,
        run_properties={
            "scanKind": "llm",
            "totalAttacks": total,
            "successfulAttacks": success,
            "asr": round(asr, 4),
            "elapsed": round(float(getattr(result, "elapsed", 0.0)), 3),
            "rulesRun": getattr(result, "rules_run", 0),
        },
    )


def scan_result_to_sarif(result) -> dict:
    """FastScanner 统一扫描结果（ScanResult 或同构对象）→ SARIF。

    优先消费 ai_risk_findings（统一 AIRiskFinding 回流）；
    为空时回退到原始 findings 并做鸭子类型映射。
    """
    findings = getattr(result, "ai_risk_findings", None)
    if not findings:
        findings = getattr(result, "findings", []) or []
    return findings_to_sarif(
        findings,
        tool_name="jianwei-fastscanner",
        tool_version="2.0",
        target=getattr(result, "target", ""),
        strategy=getattr(result, "strategy", "standard"),
        execution_successful=not getattr(result, "errors", []),
        run_properties={
            "scanKind": getattr(result, "target_type", ""),
            "rulesRun": getattr(result, "rules_run", []),
            "timedOut": getattr(result, "timed_out", []),
            "errors": [str(e) for e in getattr(result, "errors", [])],
            "elapsed": round(float(getattr(result, "elapsed", 0.0)), 3),
        },
    )

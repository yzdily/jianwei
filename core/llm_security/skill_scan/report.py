"""skill_scan 报告 —— VulnFinding 回流 + SARIF 2.1.0 导出（设计 §3.4 / §7）。

`build_sarif` 为底层；`to_sarif(result)` / `render_markdown(result)` 为对结果对象的便捷封装
（供 mcp_tool.py / 测试 / CLI 复用）。所有函数对「finding 类型」duck-typed，
兼容 analyzers.base.SkillFinding（check_type/name/枚举 severity）与携带 vuln_type 的发现。
"""
from __future__ import annotations

from .analyzers.base import SkillFinding, Severity

_TOOL_NAME = "jianwei-skill-scan"
_SARIF_VERSION = "2.1.0"

_SEV_TO_SARIF = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}
_SEV_TO_SARIF_STR = {
    "critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "none",
}


def _sev_str(sev) -> str:
    return str(getattr(sev, "value", sev)).lower()


def _rule_id(f) -> str:
    return (
        getattr(f, "check_type", None)
        or getattr(f, "vuln_type", None)
        or getattr(f, "name", None)
        or "unknown"
    )


def _title(f) -> str:
    return getattr(f, "name", None) or getattr(f, "title", None) or _rule_id(f)


def _desc(f) -> str:
    return getattr(f, "description", None) or getattr(f, "snippet", None) or getattr(f, "title", "") or ""


def build_sarif(scan_id: str, source: str, findings: list[SkillFinding]) -> dict:
    """生成 SARIF 2.1.0 文档，便于接入 DevSecOps / CI 门禁。"""
    rules: dict[str, dict] = {}
    results = []
    for f in findings:
        rule_id = _rule_id(f)
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": _title(f),
                "shortDescription": {"text": _desc(f)[:120]},
                "fullDescription": {"text": _desc(f)},
                "helpUri": "",
            }
        results.append({
            "ruleId": rule_id,
            "level": _SEV_TO_SARIF_STR.get(_sev_str(getattr(f, "severity", "info")), "warning"),
            "message": {"text": _desc(f)},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": getattr(f, "file_path", "") or ""},
                    "region": {"startLine": max(1, int(getattr(f, "line", 0) or 0))},
                }
            }],
            "properties": {
                "owasp": getattr(f, "owasp", ""),
                "severity": _sev_str(getattr(f, "severity", "")),
                "safe_to_install": getattr(f, "safe_to_install", True),
            },
        })

    return {
        "version": _SARIF_VERSION,
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": _TOOL_NAME,
                    "version": "0.1.0",
                    "informationUri": "https://github.com/yzdily/jianwei",
                    "rules": list(rules.values()),
                }
            },
            "invocations": [{
                "executionSuccessful": True,
                "properties": {"scan_id": scan_id, "source": source},
            }],
            "results": results,
            "taxonomies": [],
            "properties": {"rules_count": len(rules)},
        }],
    }


def to_sarif(result) -> dict:
    """对 SkillScanResult 生成 SARIF（补 riskScore 到 runs[0].properties）。"""
    scan_id = getattr(result, "scan_id", "") or getattr(result, "target_source", "")
    source = getattr(result, "source", "") or getattr(result, "target_source", "")
    findings = list(getattr(result, "findings", []) or [])
    doc = build_sarif(scan_id, source, findings)
    doc["runs"][0]["properties"]["riskScore"] = int(getattr(result, "risk_score", 0) or 0)
    doc["runs"][0]["properties"]["safe_to_install"] = bool(getattr(result, "safe_to_install", True))
    return doc


def render_markdown(result) -> str:
    """渲染技能供应链安全 Markdown 章节（含安装门禁）。"""
    findings = list(getattr(result, "findings", []) or [])
    score = int(getattr(result, "risk_score", 0) or 0)
    sev = str(getattr(result, "severity", "info"))
    safe = bool(getattr(result, "safe_to_install", True))
    source = getattr(result, "source", "") or getattr(result, "target_source", "")

    lines = [
        "## 技能供应链安全",
        "",
        f"- 扫描对象：`{source}`",
        f"- 风险评分：**{score}** / 100",
        f"- 综合严重级：{sev}",
        f"- 安装门禁：{'✅ 允许安装（score ≤ 50）' if safe else '⛔ 阻断安装（score > 50）'}",
        f"- 发现数：{len(findings)}",
        "",
    ]
    if findings:
        lines.append("### 发现明细")
        lines.append("")
        lines.append("| 严重级 | 类型 | 位置 | 说明 |")
        lines.append("|---|---|---|---|")
        for f in findings:
            loc = getattr(f, "file_path", "") or ""
            ln = getattr(f, "line", 0) or 0
            pos = f"{loc}:{ln}" if ln else loc
            lines.append(
                f"| {_sev_str(getattr(f, 'severity', ''))} | {_rule_id(f)} | `{pos}` | {_desc(f)[:80]} |"
            )
        lines.append("")
    return "\n".join(lines)


def exit_code_for(score: int) -> int:
    """退出码作门禁：<=50 通过(0) / >50 阻断(1)。"""
    return 0 if score <= 50 else 1

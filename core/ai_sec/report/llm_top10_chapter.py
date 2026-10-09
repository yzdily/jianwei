"""L5 报告章节 —— OWASP LLM Top 10（鉴微平台层报告，设计 §11.5）。

消费平台统一 schema `AIRiskFinding`（core.ai_sec.models），生成：
  - OWASP LLM Top 10 章节 markdown（10 类 + 3 新面分组 + 每类汇总表）
  - SARIF 2.1.0 导出（复用 skill_scan 的 build_sarif 范式并带 owasp 属性）

不修改上游 xuanjian 的 `compliance_report.py`，作为 JianWei 平台层新增模块。
单测见 tests/test_llm_top10_report.py。
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone

from core.ai_sec.models import AIRiskFinding

_TOOL_NAME = "jianwei-llm-top10"
_SARIF_VERSION = "2.1.0"

# severity(str) -> SARIF level，与 skill_scan/report.py 保持一致
_SEV_TO_SARIF = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "none",
}

_SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "": 0}

# 类别元信息：code -> (中文名, 英文主题, 简述, CWE 参考)
# 覆盖 OWASP LLM Top 10 (2025) 全 10 类 + JianWei 三个新面
OWASP_LLM_TOP10_META: dict[str, tuple[str, str, str, str]] = {
    "LLM01": ("提示注入", "Prompt Injection", "攻击者通过 crafted 输入覆盖/绕过系统指令", "CWE-77/CWE-94"),
    "LLM02": ("敏感信息泄露", "Sensitive Information Disclosure", "模型泄露训练/系统/用户敏感数据", "CWE-200"),
    "LLM03": ("供应链漏洞", "Supply Chain", "依赖/模型/技能来源不可信导致漏洞", "CWE-1104"),
    "LLM04": ("数据与模型投毒", "Data & Model Poisoning", "训练/检索数据被污染影响输出", "CWE-506"),
    "LLM05": ("输出处理不当", "Improper Output Handling", "未校验模型输出直接执行（XSS/SSRF/注入）", "CWE-116/CWE-79"),
    "LLM06": ("过度代理", "Excessive Agency", "授予过多工具/权限导致越权操作", "CWE-250"),
    "LLM07": ("系统提示泄露", "System Prompt Leakage", "系统/开发者提示被逆向提取", "CWE-200"),
    "LLM08": ("向量库越权", "Vector/DB Misuse", "检索/向量库越权访问租户数据", "CWE-285"),
    "LLM09": ("错误/误导信息", "Misinformation / Overreliance", "模型产生事实错误被过度依赖", "CWE-1284"),
    "LLM10": ("失控消耗", "Unbounded Consumption", "资源/额度被耗尽（DoS/成本）", "CWE-400"),
    "RAG": ("RAG 投毒", "RAG Poisoning (new)", "检索知识库被投毒注入恶意上下文", "CWE-506"),
    "AGENT": ("Agent 逃逸", "Agent Escape (new)", "Agent 编排越权外发/绕过约束", "CWE-841"),
    "MCP": ("MCP 滥用", "MCP Tool Abuse (new)", "MCP 工具链未授权调用/越权", "CWE-285"),
}


def _meta(code: str) -> tuple[str, str, str, str]:
    return OWASP_LLM_TOP10_META.get(code, (code, code, "", ""))


def group_by_class(findings: list[AIRiskFinding]) -> dict[str, list[AIRiskFinding]]:
    """按 OWASP 类别分组。"""
    g: dict[str, list[AIRiskFinding]] = defaultdict(list)
    for f in findings:
        g[f.owasp or "UNKNOWN"].append(f)
    return dict(g)


def _max_severity(fs: list[AIRiskFinding]) -> str:
    if not fs:
        return "-"
    return max((f.severity or "" for f in fs), key=lambda s: _SEV_RANK.get(s, 0))


def _count_severity(findings: list[AIRiskFinding]) -> dict[str, int]:
    c: dict[str, int] = defaultdict(int)
    for f in findings:
        c[(f.severity or "unknown").lower()] += 1
    return dict(c)


def _ordered_codes(groups: dict[str, list[AIRiskFinding]]) -> list[str]:
    """优先按 OWASP_LLM_TOP10_META 规范顺序，未知类尾附。"""
    known = [c for c in OWASP_LLM_TOP10_META if c in groups]
    extra = [c for c in groups if c not in OWASP_LLM_TOP10_META]
    return known + sorted(extra)


def build_llm_top10_chapter(
    findings: list[AIRiskFinding],
    title: str = "OWASP LLM Top 10 安全 Findings",
) -> str:
    """生成 OWASP LLM Top 10 章节 markdown（每类汇总表 + 明细）。"""
    groups = group_by_class(findings)
    lines = [f"## {title}", ""]

    if not findings:
        lines.append("_本次扫描未检出 OWASP LLM Top 10 类风险。_")
        return "\n".join(lines)

    lines.append("### 每类汇总")
    lines.append("")
    lines.append("| 类别 | 名称 | 发现数 | 最高严重度 |")
    lines.append("|------|------|--------|------------|")
    for code in _ordered_codes(groups):
        name_zh, *_ = _meta(code)
        sev = _max_severity(groups[code])
        lines.append(f"| {code} | {name_zh} | {len(groups[code])} | {sev} |")
    lines.append("")

    lines.append("### 发现明细")
    lines.append("")
    for code in _ordered_codes(groups):
        name_zh, name_en, desc, cwe = _meta(code)
        fs = groups[code]
        lines.append(f"#### {code} · {name_zh}（{name_en}）")
        lines.append("")
        lines.append(f"> {desc}  ·  CWE: {cwe}")
        lines.append("")
        for f in fs:
            lines.append(f"- **[{(f.severity or '?').upper()}]** `{f.vuln_type}` — {f.detail}")
            if f.evidence:
                lines.append(f"  - 证据: `{f.evidence[:200]}`")
            if f.confidence:
                eq = f.evidence_quality or "-"
                lines.append(f"  - 置信度: {f.confidence:.2f} · 证据质量: {eq} · trace: `{f.trace_id}`")
            if f.fix_suggestion:
                lines.append(f"  - 修复建议: {f.fix_suggestion}")
        lines.append("")

    return "\n".join(lines)


def build_llm_top10_sarif(
    scan_id: str,
    findings: list[AIRiskFinding],
    source: str = "jianwei-llm-top10",
) -> dict:
    """生成 SARIF 2.1.0 文档，便于接入 DevSecOps / CI 门禁（设计 §11.5）。"""
    rules: dict[str, dict] = {}
    results = []
    for f in findings:
        rid = f.vuln_type or f.rule_tag or "llm_vuln"
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": rid,
                "shortDescription": {"text": f"{f.owasp}: {f.detail[:120]}"},
                "fullDescription": {"text": f.detail},
                "helpUri": "",
            }
        results.append({
            "ruleId": rid,
            "level": _SEV_TO_SARIF.get((f.severity or "medium").lower(), "warning"),
            "message": {"text": f.detail},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.url or "mock://llm"},
                    "region": {"startLine": 1},
                }
            }],
            "properties": {
                "owasp": f.owasp,
                "severity": f.severity,
                "confidence": round(f.confidence, 2),
                "evidence_quality": f.evidence_quality,
                "trace_id": f.trace_id,
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
                }
            },
            "invocations": [{
                "executionSuccessful": True,
                "properties": {"scan_id": scan_id, "source": source},
            }],
            "results": results,
            "taxonomies": [],
            "properties": {"rules_count": len(rules), "findings_count": len(findings)},
        }],
    }


def build_report(
    target_url: str,
    findings: list[AIRiskFinding],
    scan_id: str = "",
    benchmark_per_class: dict | None = None,
    include_atlas: bool = True,
) -> str:
    """生成完整 OWASP LLM Top 10 报告（执行摘要 + 章节 + 可选基准表 + ATLAS 映射）。"""
    total = len(findings)
    by_sev = _count_severity(findings)
    sev_str = ", ".join(f"{k}={v}" for k, v in sorted(by_sev.items(), key=lambda kv: -_SEV_RANK.get(kv[0], 0))) or "无"

    lines = ["# 鉴微 AI 安全风险报告（OWASP LLM Top 10）", ""]
    lines.append(f"- 目标: `{target_url}`")
    lines.append(f"- 扫描 ID: `{scan_id or '-'}`")
    lines.append(f"- 生成时间: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append(f"- 总发现: **{total}**")
    lines.append(f"- 严重度分布: {sev_str}")
    lines.append("")
    lines.append("> ⚠️ 仅限授权安全测试使用。本报告依据 OWASP LLM Top 10 (2025) 生成。")
    lines.append("")
    lines.append(build_llm_top10_chapter(findings))

    if benchmark_per_class:
        lines.append("## 基准评测（per_class）")
        lines.append("")
        lines.append("| 类别 | TP | FP | TN | FN | 召回 | 误报率 |")
        lines.append("|------|----|----|----|----|------|--------|")
        for code, m in benchmark_per_class.items():
            tp = m.get("tp", 0); fp = m.get("fp", 0); tn = m.get("tn", 0); fn = m.get("fn", 0)
            recall = tp / (tp + fn) if (tp + fn) else 1.0
            fpr = fp / (fp + tn) if (fp + tn) else 0.0
            name_zh, *_ = _meta(code)
            lines.append(f"| {code} {name_zh} | {tp} | {fp} | {tn} | {fn} | {recall:.0%} | {fpr:.0%} |")
        lines.append("")

    if include_atlas:
        from .atlas_chapter import build_atlas_chapter
        lines.append(build_atlas_chapter(findings))

    return "\n".join(lines)

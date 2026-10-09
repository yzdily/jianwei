"""L5 · 完整合规报告组装（覆盖矩阵 + 详情 + PoC + 整改清单 + 等保对齐）。

在既有 `llm_top10_chapter.build_report`（章节 + ATLAS + SARIF）之上，补齐交付所需四段：
  ① 覆盖矩阵   （功能点 × 漏洞域，可传引擎 testflow 导出的矩阵）
  ② 漏洞详情   （复用 OWASP LLM Top10 章节）
  ③ PoC 清单   （每条确认漏洞的可复现证据：payload + 响应 + trace_id）
  ④ 整改清单 + 等保对齐（OWASP → GB/T 22239 参考条款映射，非认证）

设计依据：《鉴微优化方案》§4。不修改上游引擎的 `compliance_report.py`。
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone

from core.ai_sec.models import AIRiskFinding
from core.ai_sec.report.llm_top10_chapter import (
    OWASP_LLM_TOP10_META,
    _meta,
    build_llm_top10_chapter,
)

__all__ = [
    "build_full_report",
    "build_coverage_matrix_section",
    "build_poc_section",
    "build_remediation_section",
    "OWASP_TO_DENGBAO",
]

# OWASP LLM 类别 → 等保 2.0（GB/T 22239-2019）三级安全通用要求**参考条款**
# 注：这是"风险域→控制项"的工程参考对齐，不构成等保测评结论。
OWASP_TO_DENGBAO: dict[str, tuple[str, str]] = {
    "LLM01": ("8.1.4.2 访问控制", "对输入/指令做边界隔离，禁止用户输入提升为系统指令"),
    "LLM02": ("8.1.4.8 数据保密性", "敏感数据加密与最小化；输出侧脱敏过滤"),
    "LLM03": ("8.1.3.3 恶意代码防范", "第三方依赖/技能来源校验，供应链可信"),
    "LLM04": ("8.1.4.7 数据完整性", "训练/检索数据完整性校验，防投毒"),
    "LLM05": ("8.1.4.2 访问控制", "模型输出不得直接进入执行/渲染通道"),
    "LLM06": ("8.1.4.2 访问控制", "工具/权限最小化，敏感动作二次确认"),
    "LLM07": ("8.1.4.8 数据保密性", "系统提示不得进入可被用户复述的通道"),
    "LLM08": ("8.1.4.2 访问控制", "检索/向量库按主体强制 ACL"),
    "LLM09": ("8.1.4.3 安全审计", "关键结论可溯源、可审计，防误导"),
    "LLM10": ("8.1.4.1 身份鉴别", "配额与速率限制，防资源耗尽"),
    "RAG": ("8.1.4.7 数据完整性", "知识库来源审计与投毒检测"),
    "AGENT": ("8.1.4.2 访问控制", "Agent 目标完整性与越权检测"),
    "MCP": ("8.1.3.2 入侵防范", "MCP 工具最小权限与调用审计"),
}

_SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "": 0}


def _sev(f) -> str:
    return (getattr(f, "severity", "") or "").lower()


def build_coverage_matrix_section(coverage: list[dict] | None) -> str:
    """覆盖矩阵段落。coverage: [{endpoint/fp, domain, status}]（可来自引擎 testflow 导出）。"""
    lines = ["## 覆盖矩阵（功能点 × 漏洞域）", ""]
    if not coverage:
        lines.append("_未提供覆盖矩阵（可传引擎 testflow 导出的矩阵：`[{endpoint, domain, status}]`）。_")
        return "\n".join(lines)

    counts: dict[str, int] = defaultdict(int)
    for c in coverage:
        counts[str(c.get("status", "unknown"))] += 1
    total = len(coverage)
    lines.append(f"- 总格数：{total}")
    for status, n in sorted(counts.items()):
        lines.append(f"  - `{status}`：{n}")
    lines.append("")
    lines.append("| 功能点/端点 | 域 | 结论 |")
    lines.append("|---|---|---|")
    for c in coverage:
        lines.append(f"| `{c.get('endpoint') or c.get('fp', '?')}` | {c.get('domain', '')} | {c.get('status', '')} |")
    lines.append("")
    return "\n".join(lines)


def build_poc_section(findings: list[AIRiskFinding]) -> str:
    """PoC 清单：每条发现的 payload + 响应 + trace_id（可复现证据）。"""
    lines = ["## PoC / 证据清单", ""]
    with_poc = [f for f in findings if getattr(f, "payload", "") or getattr(f, "response_snippet", "")]
    if not with_poc:
        lines.append("_本次未产出带可复现证据（payload/响应）的确认发现。_")
        return "\n".join(lines)
    for i, f in enumerate(with_poc, 1):
        lines.append(f"### PoC-{i:02d} · {f.owasp} `{f.vuln_type}`（{_sev(f) or '?'}）")
        lines.append("")
        lines.append(f"- 目标：`{f.url}`")
        lines.append(f"- 溯源：`{f.trace_id or '-'}` · 证据质量：{f.evidence_quality or '-'}")
        if f.payload:
            lines.append("- 请求 payload：")
            lines.append("  ```text")
            lines.append(f"  {str(f.payload)[:400]}")
            lines.append("  ```")
        snippet = f.response_snippet or f.evidence
        if snippet:
            lines.append("- 响应证据：")
            lines.append("  ```text")
            lines.append(f"  {str(snippet)[:400]}")
            lines.append("  ```")
        if f.fix_suggestion:
            lines.append(f"- 修复建议：{f.fix_suggestion}")
        lines.append("")
    return "\n".join(lines)


def build_remediation_section(findings: list[AIRiskFinding]) -> str:
    """整改清单 + 等保对齐（OWASP 类别 → GB/T 22239 参考条款）。"""
    lines = ["## 整改清单与等保对齐", ""]
    if not findings:
        lines.append("_无发现，无需整改。_")
        return "\n".join(lines)

    by_code: dict[str, list[AIRiskFinding]] = defaultdict(list)
    for f in findings:
        by_code[f.owasp or "UNKNOWN"].append(f)

    lines.append("| 类别 | 名称 | 发现数 | 最高严重度 | 等保参考 | 整改要点 |")
    lines.append("|---|---|---|---|---|---|")
    for code in sorted(by_code, key=lambda c: -_SEV_RANK.get(_sev(max(by_code[c], key=lambda f: _SEV_RANK.get(_sev(f), 0))), 0)):
        fs = by_code[code]
        name_zh, *_ = _meta(code)
        top = max(fs, key=lambda f: _SEV_RANK.get(_sev(f), 0))
        clause, point = OWASP_TO_DENGBAO.get(code, ("—", "（无参考映射）"))
        fix = top.fix_suggestion or point
        lines.append(f"| {code} | {name_zh} | {len(fs)} | {_sev(top) or '-'} | {clause} | {fix[:80]} |")
    lines.append("")
    lines.append("> ⚠️ 等保条款为**工程参考对齐**（非等保测评结论）。详见 OWASP LLM Top 10 与 GB/T 22239-2019。")
    return "\n".join(lines)


def build_full_report(
    findings: list[AIRiskFinding],
    *,
    target_url: str = "",
    scan_id: str = "",
    coverage: list[dict] | None = None,
    metrics=None,
    baseline: dict | None = None,
    include: tuple[str, ...] = ("summary", "coverage", "detail", "poc", "remediation", "metrics", "atlas"),
) -> str:
    """组装完整 L5 报告（Markdown）。

    Args:
        findings: AIRiskFinding 列表
        coverage: 覆盖矩阵（可选）
        metrics: MetricSummary（可选）
        baseline: 指标基线 dict（可选，用于 Δ）
        include: 要包含的段落
    """
    total = len(findings)
    lines: list[str] = []

    if "summary" in include:
        by_sev: dict[str, int] = defaultdict(int)
        for f in findings:
            by_sev[_sev(f) or "unknown"] += 1
        sev_str = ", ".join(
            f"{k}={v}" for k, v in sorted(by_sev.items(), key=lambda kv: -_SEV_RANK.get(kv[0], 0))
        ) or "无"
        lines += [
            "# 鉴微 AI 安全合规报告",
            "",
            f"- 目标: `{target_url or '-'}`",
            f"- 扫描 ID: `{scan_id or '-'}`",
            f"- 生成时间: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            f"- 总发现: **{total}**",
            f"- 严重度分布: {sev_str}",
            "",
            "> ⚠️ 仅限授权安全测试使用。",
            "",
        ]

    if "coverage" in include:
        lines.append(build_coverage_matrix_section(coverage))

    if "detail" in include:
        lines.append(build_llm_top10_chapter(findings))
        lines.append("")

    if "poc" in include:
        lines.append(build_poc_section(findings))

    if "remediation" in include:
        lines.append(build_remediation_section(findings))

    if "metrics" in include and metrics is not None:
        from core.ai_sec.metrics.hook import render_metrics_section

        lines.append(render_metrics_section(metrics))
        if baseline is not None:
            from core.ai_sec.metrics.baseline import compare

            cmp = compare(metrics, baseline)
            lines.append("### 基线回归对比")
            lines.append("")
            lines.append(f"- 是否劣化：{'❌ 有回归' if not cmp['ok'] else '✅ 无回归'}")
            for m, d in cmp["deltas"].items():
                lines.append(f"  - {m}: Δ {d:+.3f}")
            lines.append("")

    if "atlas" in include:
        from core.ai_sec.report.atlas_chapter import build_atlas_chapter

        lines.append(build_atlas_chapter(findings))

    return "\n".join(lines)

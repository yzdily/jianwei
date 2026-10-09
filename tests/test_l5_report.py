"""L5 · 完整合规报告测试。"""
from __future__ import annotations

from core.ai_sec.models import AIRiskFinding
from core.ai_sec.report import (
    OWASP_TO_DENGBAO,
    build_coverage_matrix_section,
    build_full_report,
    build_poc_section,
    build_remediation_section,
)


def _f(owasp="LLM01", sev="high", vuln="llm_prompt_injection", payload="P", snip="S"):
    return AIRiskFinding(
        owasp=owasp, vuln_type=vuln, severity=sev, url="http://t/v1/chat", detail="d",
        evidence="ev", payload=payload, response_snippet=snip,
        fix_suggestion="fix it", confidence=0.9, evidence_quality="body_confirmed",
        trace_id="JW-LLM01-1",
    )


class TestSections:
    def test_coverage_matrix_with_data(self):
        cov = [
            {"endpoint": "/v1/chat", "domain": "ai", "status": "reported"},
            {"endpoint": "/v1/rag", "domain": "ai", "status": "needs_follow_up"},
        ]
        md = build_coverage_matrix_section(cov)
        assert "覆盖矩阵" in md
        assert "/v1/chat" in md and "needs_follow_up" in md

    def test_coverage_matrix_empty(self):
        assert "未提供覆盖矩阵" in build_coverage_matrix_section(None)

    def test_poc_section(self):
        md = build_poc_section([_f()])
        assert "PoC" in md
        assert "P" in md and "S" in md
        assert "JW-LLM01-1" in md

    def test_remediation_maps_dengbao(self):
        md = build_remediation_section([_f("LLM01"), _f("LLM08", vuln="llm_rag_acl")])
        assert "整改清单" in md
        assert OWASP_TO_DENGBAO["LLM01"][0] in md
        assert OWASP_TO_DENGBAO["LLM08"][0] in md


class TestFullReport:
    def test_full_report_all_sections(self):
        md = build_full_report(
            [_f(), _f("LLM02", sev="critical", vuln="llm_sensitive_leak")],
            target_url="http://t/v1/chat", scan_id="JW-1",
            coverage=[{"endpoint": "/v1/chat", "domain": "ai", "status": "reported"}],
        )
        assert "鉴微 AI 安全合规报告" in md
        assert "覆盖矩阵" in md
        assert "OWASP LLM Top 10" in md
        assert "PoC" in md
        assert "整改清单" in md
        assert "ATLAS" in md or "MITRE" in md

    def test_include_filter(self):
        md = build_full_report([_f()], include=("detail",))
        assert "OWASP LLM Top 10" in md
        assert "覆盖矩阵" not in md and "整改清单" not in md

    def test_report_with_metrics_and_baseline(self):
        from core.ai_sec.metrics import metrics_for_findings

        metrics = metrics_for_findings([_f()], total=4)
        md = build_full_report(
            [_f()], metrics=metrics, baseline={"asr": 0.1},
            include=("metrics",),
        )
        assert "攻击成功率" in md
        assert "基线回归对比" in md

    def test_report_empty_findings(self):
        md = build_full_report([], target_url="http://t")
        assert "总发现: **0**" in md
        assert "无发现，无需整改" in md

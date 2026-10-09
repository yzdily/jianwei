"""L5 报告章节单测（设计 §11.5 OWASP LLM Top 10 章节）。

验证 core/ai_sec/report 对 AIRiskFinding 的分组、章节渲染、SARIF 导出。
"""
import asyncio
import pytest

from core.ai_sec.models import AIRiskFinding
from core.ai_sec.report import (
    build_llm_top10_chapter,
    build_llm_top10_sarif,
    build_report,
    group_by_class,
)


def _mk(owasp, vuln_type, severity, evidence="", confidence=0.9, trace_id=""):
    return AIRiskFinding(
        owasp=owasp,
        vuln_type=vuln_type,
        severity=severity,
        url="http://127.0.0.1:5000/chat/lab1",
        detail=f"[{owasp}] 示例发现 {vuln_type}",
        evidence=evidence,
        confidence=confidence,
        evidence_quality="body_confirmed",
        trace_id=trace_id or f"tr-{owasp}",
        fix_suggestion="升级 prompt 护栏",
    )


def test_empty_chapter():
    md = build_llm_top10_chapter([])
    assert "未检出" in md


def test_group_and_order():
    fs = [
        _mk("LLM06", "llm_excessive_agency", "critical", "ami-id"),
        _mk("LLM01", "llm_prompt_injection", "high", "系统提示"),
        _mk("RAG", "llm_rag_poison", "high", "Admin"),
        _mk("LLM01", "llm_prompt_injection", "medium", "忽略指令"),
    ]
    g = group_by_class(fs)
    assert set(g) == {"LLM01", "LLM06", "RAG"}
    # 规范顺序：LLM01 在 LLM06 前，RAG 在末
    ordered = [c for c in __import__("core.ai_sec.report.llm_top10_chapter", fromlist=["_ordered_codes"])._ordered_codes(g)]
    assert ordered.index("LLM01") < ordered.index("LLM06") < ordered.index("RAG")


def test_chapter_contains_summary_and_detail():
    fs = [_mk("LLM01", "llm_prompt_injection", "high", "系统提示")]
    md = build_llm_top10_chapter(fs)
    assert "每类汇总" in md
    assert "发现明细" in md
    assert "LLM01" in md
    assert "提示注入" in md
    assert "CWE-77/CWE-94" in md  # LLM01 CWE 参考


def test_sarif_structure():
    fs = [_mk("LLM06", "llm_excessive_agency", "critical", "ami-id", trace_id="tr-llm06")]
    sarif = build_llm_top10_sarif("scan-001", fs)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "jianwei-llm-top10"
    assert len(sarif["runs"][0]["results"]) == 1
    r = sarif["runs"][0]["results"][0]
    assert r["level"] == "error"  # critical -> error
    assert r["properties"]["owasp"] == "LLM06"
    assert r["properties"]["trace_id"] == "tr-llm06"
    assert sarif["runs"][0]["properties"]["findings_count"] == 1


def test_build_report_warning_and_benchmark():
    fs = [_mk("LLM01", "llm_prompt_injection", "high", "系统提示")]
    per_class = {"LLM01": {"tp": 1, "fp": 0, "tn": 1, "fn": 0}}
    md = build_report("http://t", fs, scan_id="s1", benchmark_per_class=per_class)
    assert "仅限授权安全测试" in md
    assert "基准评测" in md
    assert "100%" in md  # 召回/误报率渲染

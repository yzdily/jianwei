"""MITRE ATLAS 映射章节单测（设计 §11.5）。"""
from core.ai_sec.models import AIRiskFinding
from core.ai_sec.report import ATLAS_MAPPING, build_atlas_chapter, build_report


def _mk(owasp):
    return AIRiskFinding(
        owasp=owasp, vuln_type=f"llm_{owasp.lower()}_demo", severity="high",
        url="http://127.0.0.1:5000/chat/lab", detail=f"[{owasp}] demo",
        evidence="x", confidence=0.9, evidence_quality="body_confirmed",
    )


def test_mapping_covers_all_13_classes():
    # 10 OWASP + RAG/AGENT/MCP
    assert set(ATLAS_MAPPING) == {
        "LLM01", "LLM02", "LLM03", "LLM04", "LLM05",
        "LLM06", "LLM07", "LLM08", "LLM09", "LLM10",
        "RAG", "AGENT", "MCP",
    }
    for code, techs in ATLAS_MAPPING.items():
        assert techs, f"{code} 应有映射"
        for tactic, tid, name in techs:
            assert tactic and tid and name


def test_atlas_chapter_static_table():
    md = build_atlas_chapter([])
    assert "MITRE ATLAS" in md
    assert "AML.T0051" in md  # LLM01 Prompt Injection
    assert "AML.T0056" in md  # LLM07 Meta Prompt Extraction
    assert "v5.4.0" in md


def test_atlas_chapter_marks_detected():
    md = build_atlas_chapter([_mk("LLM01"), _mk("LLM06")])
    assert "✅命中" in md
    assert "本次扫描命中 2 个" in md


def test_build_report_includes_atlas_by_default():
    fs = [_mk("LLM01")]
    md = build_report("http://t", fs, scan_id="s1")
    assert "MITRE ATLAS" in md
    assert "AML.T0051" in md


def test_build_report_can_disable_atlas():
    fs = [_mk("LLM01")]
    md = build_report("http://t", fs, scan_id="s1", include_atlas=False)
    assert "MITRE ATLAS" not in md

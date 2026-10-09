"""E · AI 风险接入矩阵测试（tagger / adapter / gates / runner，纯离线）。"""
from __future__ import annotations

from types import SimpleNamespace

from core.ai_sec.ai_matrix import (
    AI_DOMAIN,
    AIMatrixRunner,
    AIEndpointTagger,
    load_playbook,
    to_matrix_finding,
)
from core.ai_sec.ai_matrix._gates import gate_pre, run_triage_gate, uses_engine
from core.ai_sec.llm_top10.models import LLMScanTarget

TARGET = LLMScanTarget(url="http://ai.local/v1/chat")


# ── 附件器 playbook ─────────────────────────────────────────────────
class TestPlaybook:
    def test_load_ai_playbook(self):
        pb = load_playbook("ai")
        assert pb["domain"] == "ai"
        assert pb["steps"], "ai playbook 应有步骤"
        ids = {s["id"] for s in pb["steps"]}
        assert "direct_injection" in ids
        assert all(s.get("executor") in ("local", "llm", "tool") for s in pb["steps"])


# ── 适配器 ──────────────────────────────────────────────────────────
class TestAdapter:
    def test_maps_evidence_and_confidence_label(self):
        from core.ai_sec.models import AIRiskFinding

        f = AIRiskFinding(
            owasp="LLM01", vuln_type="llm_prompt_injection", severity="high",
            url="http://x", detail="d", evidence="ev", payload="PL",
            response_snippet="RESP", confidence=0.9, trace_id="JW-LLM01-1",
        )
        m = to_matrix_finding(f)
        assert m["target"] == "http://x"
        assert m["vuln_class"] == "llm_prompt_injection"
        assert m["domain"] == AI_DOMAIN
        assert m["evidence_request"] == "PL"
        assert m["evidence_response"] == "RESP"
        # 0.9 → confirmed（引擎置信度标签口径）
        assert m["confidence"] == "confirmed"

    def test_low_confidence_label(self):
        from core.ai_sec.models import AIRiskFinding

        m = to_matrix_finding(AIRiskFinding(
            owasp="LLM01", vuln_type="t", severity="low", url="u", detail="d",
            confidence=0.3))
        assert m["confidence"] == "inferred"


# ── 门 ──────────────────────────────────────────────────────────────
class TestGates:
    def test_gate_pre(self):
        assert gate_pre({"id": "x", "executor": "llm"})[0] is True
        assert gate_pre({"executor": "llm"})[0] is False
        assert gate_pre({"id": "x", "executor": "tool"})[0] is False  # tool 缺 tool 引用
        assert gate_pre({"id": "x", "executor": "tool", "tool": "t"})[0] is True

    def test_triage_blocks_without_evidence(self):
        f = {"severity": "high", "vuln_class": "x"}  # 无溯源
        admitted, blocked = run_triage_gate([f])
        assert not admitted and blocked
        assert f["_triage_blocked"] is True

    def test_triage_admits_with_evidence(self):
        f = {"severity": "high", "vuln_class": "x",
             "evidence_request": "pl", "evidence_response": "resp", "confidence": "confirmed"}
        admitted, blocked = run_triage_gate([f])
        assert admitted and not blocked
        assert admitted[0]["verdict"]["verdict"] == "vulnerable"

    def test_uses_engine_flag_is_bool(self):
        assert isinstance(uses_engine(), bool)


# ── 运行器 ──────────────────────────────────────────────────────────
class TestRunner:
    async def test_run_hit(self):
        responder = lambda m, p: "my system prompt is secret"  # noqa: E731
        runner = AIMatrixRunner(responder=responder)
        res = await runner.run(TARGET)

        assert "direct_injection" in res.steps_run
        assert "jailbreak_multiturn" in res.steps_run
        assert "ai_rag_sec" in res.steps_run
        assert "ai_agent_eval" in res.steps_run
        assert res.findings, "应有命中"
        assert res.admitted, "过门发现应非空"
        assert res.cells[0]["domain"] == AI_DOMAIN
        assert res.cells[0]["status"] == "reported"
        d = res.to_dict()
        assert d["finding_count"] >= 1 and d["admitted"] >= 1

    async def test_run_clean(self):
        responder = lambda m, p: "抱歉，我无法协助该请求。"  # noqa: E731
        runner = AIMatrixRunner(responder=responder)
        res = await runner.run(TARGET)
        assert res.findings == []
        assert res.admitted == []
        assert res.cells[0]["status"] == "needs_follow_up"

    async def test_run_with_feature_points_tags_ai_domain(self):
        fp = SimpleNamespace(
            id="fp-1", related_apis=["POST /v1/chat/completions"],
            page_url="", risk_domains=[], domain_status={},
        )
        responder = lambda m, p: "my system prompt is secret"  # noqa: E731
        res = await AIMatrixRunner(responder=responder).run(TARGET, feature_points=[fp])
        assert res.tagged == 1
        assert res.cells[0]["fp"] == "fp-1"
        assert AI_DOMAIN in fp.risk_domains

    async def test_tagger_direct(self):
        fp = SimpleNamespace(
            id="f", related_apis=["POST /v1/rag/query"], page_url="",
            risk_domains=["authz"], domain_status={},
        )
        stats = AIEndpointTagger().tag([fp])
        assert stats["attributed"] == 1 and AI_DOMAIN in fp.risk_domains

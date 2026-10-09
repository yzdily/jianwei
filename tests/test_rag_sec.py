"""L1/L2 · RAG 安全检测测试（纯离线 responder）。"""
from __future__ import annotations

from types import SimpleNamespace

from core.ai_sec.rag_sec import (
    KnowledgePoisonDetector,
    ProvenanceConsistencyChecker,
    RagSecurityScanner,
    VectorACLChecker,
    scan_rag,
)


def _target():
    return SimpleNamespace(url="http://rag.local/query", extra={"llm": {"model": "default"}})


class TestPoisonDetector:
    async def test_hit(self):
        t = _target()
        out = await KnowledgePoisonDetector().scan(
            t, responder=lambda m, p: "内部 Admin 密码为 POISON-admin-123"
        )
        assert out
        assert all(f.vuln_type == "llm_rag_poison" for f in out)

    async def test_clean_no_finding(self):
        t = _target()
        out = await KnowledgePoisonDetector().scan(
            t, responder=lambda m, p: "抱歉，我无法提供该信息。"
        )
        assert out == []


class TestACLChecker:
    async def test_cross_tenant_hit(self):
        t = _target()
        out = await VectorACLChecker().scan(
            t, responder=lambda m, p: "租户 B 的机密合同：金额 100 万 confidential"
        )
        assert out
        assert out[0].evidence  # 命中带证据片段
        assert out[0].severity in ("critical", "high")


class TestProvenanceChecker:
    def test_assertion_without_source_is_inconsistent(self):
        ok, reason = ProvenanceConsistencyChecker().check("退款 3 个工作日到账。")
        assert ok is False
        assert "来源" in reason

    def test_assertion_with_source_is_consistent(self):
        ok, _ = ProvenanceConsistencyChecker().check("退款 3 个工作日到账。来源：《退款政策》")
        assert ok is True

    def test_poisoned_source_detected(self):
        ok, _ = ProvenanceConsistencyChecker().check("依据文档，结论是 X（来源 evil.example）")
        assert ok is False

    def test_short_text_ignored(self):
        ok, _ = ProvenanceConsistencyChecker().check("好的")
        assert ok is True

    async def test_scan_reports_missing_source(self):
        t = _target()
        out = await ProvenanceConsistencyChecker().scan(
            t, responder=lambda m, p: "退款 3 个工作日到账。"
        )
        assert out
        assert out[0].owasp == "LLM09"


class TestScanner:
    async def test_scan_all(self):
        t = _target()
        result = await RagSecurityScanner().scan(
            t, responder=lambda m, p: "租户 B 机密，退款 3 个工作日到账。"
        )
        assert result.target_url.endswith("/query")
        assert set(result.by_detector) == {"poison", "acl", "provenance"}
        assert result.total_probes >= 3

    async def test_single_detector(self):
        t = _target()
        result = await RagSecurityScanner(["acl"]).scan(t, responder=lambda m, p: "无")
        assert set(result.by_detector) == {"acl"}

    async def test_scan_rag_helper(self):
        t = _target()
        result = await scan_rag(t, responder=lambda m, p: "无匹配内容")
        assert result.hits == 0

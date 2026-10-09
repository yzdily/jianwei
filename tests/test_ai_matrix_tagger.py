"""E2 · `ai` 域端点归属器测试（纯离线）。"""
from __future__ import annotations

from types import SimpleNamespace

from core.ai_sec.ai_matrix import AI_DOMAIN, AIEndpointTagger


def _fp(path: str, method: str = "GET", domains=None):
    return SimpleNamespace(
        related_apis=[f"{method} {path}"],
        page_url="",
        risk_domains=list(domains or []),
        domain_status={},
    )


class TestAIEndpointTagger:
    def test_chat_endpoint_tagged(self):
        t = AIEndpointTagger()
        fp = _fp("/v1/chat/completions", "POST")
        stats = t.tag([fp])
        assert stats["attributed"] == 1
        assert AI_DOMAIN in fp.risk_domains
        assert fp.domain_status[AI_DOMAIN] == "needs_follow_up"
        assert stats["via"] == "sidecar"

    def test_non_ai_endpoint_untouched(self):
        t = AIEndpointTagger()
        fp = _fp("/api/orders/list")
        stats = t.tag([fp])
        assert stats["attributed"] == 0
        assert fp.risk_domains == []
        assert fp.domain_status == {}

    def test_only_appends_preserving_engine_domains(self):
        t = AIEndpointTagger()
        fp = _fp("/api/agent/run", "POST", domains=["authz", "business"])
        t.tag([fp])
        assert fp.risk_domains[:2] == ["authz", "business"]
        assert AI_DOMAIN in fp.risk_domains

    def test_is_ai_path(self):
        t = AIEndpointTagger()
        assert t.is_ai_path("/v1/embeddings")
        assert t.is_ai_path("/mcp/tools")
        assert not t.is_ai_path("/static/logo.png")
        assert not t.is_ai_path("/api/login")

    def test_dict_feature_point_supported(self):
        t = AIEndpointTagger()
        fp = {"related_apis": ["POST /v1/rag/query"], "risk_domains": [], "domain_status": {}}
        stats = t.tag([fp])
        assert stats["attributed"] == 1
        assert AI_DOMAIN in fp["risk_domains"]

    def test_custom_keywords(self):
        t = AIEndpointTagger(keywords=["llm"])
        assert t.is_ai_path("/my/llm/endpoint")
        assert not t.is_ai_path("/v1/chat")

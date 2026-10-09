"""M2b 验证：代理/合规证书抓包 → 流量语料 → 运行时扩界（关 0903 F11 工程闭环）。

硬指标（roadmap §3 / milestones §2）：
- ProxyTrafficSource 解析 mitmproxy 流导出 / 访问日志 → TrafficCorpus → scope 扩界。
- ComplianceCertSource 解析 TLS 证书 SAN/CN 域名 → scope 扩界。
- 扩界受 authorized 白名单约束（F17 思想）：越权候选被拒绝。
- 不破边界：仅消费 DigPoolSession.scope，玄鉴侧零改动。

fixtures 位于 tests/fixtures/digpool/。
"""
from __future__ import annotations

from pathlib import Path

import pytest

from core.digpool.session import DigPoolSession

_FIXTURES = Path(__file__).parent / "fixtures" / "digpool"


async def test_proxy_dump_expands_scope_and_rejects_out_of_authorized():
    session = DigPoolSession(scope={"domains": ["example.com"], "authorized": ["example.com"]})
    update = await session.ingest_proxy_capture(str(_FIXTURES / "proxy_flows.jsonl"))
    # 关联子域被纳入（硬指标：scope_after.domains ⊋ scope_before.domains）
    assert "api.example.com" in session.scope.domains
    assert "cdn.example.com" in session.scope.domains
    assert "admin.example.com" in session.scope.domains
    # 越权域被拒绝（F17 授权门）
    assert "evil-unrelated.com" in update.rejected_domains
    assert update.has_change is True


async def test_cert_text_extracts_san_domains():
    text = ( _FIXTURES / "cert_san.txt").read_text(encoding="utf-8")
    session = DigPoolSession(scope={"domains": ["example.com"], "authorized": ["example.com"]})
    update = await session.ingest_compliance_certs(text, is_text=True)
    for d in ("api.example.com", "cdn.example.com", "admin.example.com"):
        assert d in session.scope.domains, f"证书 SAN 域名未纳入：{d}"
    assert update.has_change is True


async def test_cert_json_dump_extracts_domains():
    session = DigPoolSession(scope={"domains": ["example.com"], "authorized": ["example.com"]})
    update = await session.ingest_compliance_certs(str(_FIXTURES / "cert_san.json"))
    assert "api.example.com" in session.scope.domains
    assert "cdn.example.com" in session.scope.domains
    assert "admin.example.com" in session.scope.domains
    assert update.has_change is True


async def test_proxy_inline_records_via_session():
    session = DigPoolSession(scope={"domains": ["example.com"], "authorized": ["example.com"]})
    update = await session.ingest_proxy_capture(
        "", inline_records=[{"host": "api.example.com"}, {"host": "evil.com"}]
    )
    assert "api.example.com" in session.scope.domains
    assert "evil.com" in update.rejected_domains


# ---------------------------------------------------------------------------
# Web 入口（SSE 用 TestClient）
# ---------------------------------------------------------------------------

def test_web_ingest_proxy_endpoint():
    from fastapi.testclient import TestClient

    from web.api import create_app

    client = TestClient(create_app())
    resp = client.post("/api/digpool/ingest/proxy", json={
        "records": [{"host": "api.example.com"}, {"host": "evil.com"}],
        "scope": {"domains": ["example.com"], "authorized": ["example.com"]},
    })
    assert resp.status_code == 200
    body = resp.json()
    assert body["source"] == "proxy"
    assert "api.example.com" in body["scope"]["domains"]
    assert "evil.com" in body["update"]["rejected_domains"]


def test_web_ingest_cert_endpoint():
    from fastapi.testclient import TestClient

    from web.api import create_app

    text = ( _FIXTURES / "cert_san.txt").read_text(encoding="utf-8")
    client = TestClient(create_app())
    resp = client.post("/api/digpool/ingest/cert", json={
        "cert_text": text,
        "scope": {"domains": ["example.com"], "authorized": ["example.com"]},
    })
    assert resp.status_code == 200
    body = resp.json()
    assert body["source"] == "compliance-cert"
    assert "api.example.com" in body["scope"]["domains"]
    assert "admin.example.com" in body["scope"]["domains"]

"""web/api/ai_sec_api.py 端到端冒烟（TestClient）。

覆盖：report/scan、report/from-findings、report 取回 markdown/sarif、metrics/summary。
不依赖真实 LLM 靶场：report/scan 用 mock finding 注入 FastScanner 较复杂，
因此本报告端点主要验证 from-findings + 取回 + metrics 闭环，report/scan 验证可正常调用（被动扫描可能 0 命中）。
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from web.api import create_app


@pytest.fixture
def client():
    app = create_app()
    return TestClient(app)


SAMPLE_FINDINGS = [
    {
        "owasp": "LLM01", "vuln_type": "llm_prompt_injection", "severity": "high",
        "url": "http://127.0.0.1:5000/chat/<lab>", "detail": "检测到系统提示泄露",
        "evidence": "系统提示", "confidence": 0.95, "evidence_quality": "body_confirmed",
        "trace_id": "tr-llm01", "fix_suggestion": "启用提示注入护栏",
    },
    {
        "owasp": "LLM06", "vuln_type": "llm_excessive_agency", "severity": "critical",
        "url": "http://127.0.0.1:5000/chat/<lab>", "detail": "检测到 SSRF 工具调用",
        "evidence": "ami-id", "confidence": 0.9, "evidence_quality": "body_confirmed",
        "trace_id": "tr-llm06", "fix_suggestion": "收紧工具权限",
    },
]


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["service"] == "jianwei-api"


def test_report_from_findings_and_fetch(client):
    # 1) 生成报告
    r = client.post("/api/ai-sec/report/from-findings", json={
        "target_url": "http://127.0.0.1:5000/chat/<lab>",
        "findings": SAMPLE_FINDINGS,
    })
    assert r.status_code == 200, r.text
    body = r.json()
    scan_id = body["scan_id"]
    assert body["findings_count"] == 2
    md = body["report_markdown"]
    assert "OWASP LLM Top 10" in md
    assert "LLM01" in md and "LLM06" in md
    # 默认报告含 MITRE ATLAS 映射章节
    assert "MITRE ATLAS" in md
    assert "AML.T0051" in md  # LLM01 Prompt Injection

    # 2) 取回 markdown
    r2 = client.get(f"/api/ai-sec/report/{scan_id}")
    assert r2.status_code == 200
    assert r2.text == md

    # 3) 取回 SARIF
    r3 = client.get(f"/api/ai-sec/report/{scan_id}/sarif")
    assert r3.status_code == 200
    sarif = r3.json()
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["properties"]["findings_count"] == 2
    # SARIF 带 owasp 属性
    assert any(res["properties"]["owasp"] == "LLM01" for res in sarif["runs"][0]["results"])


def test_report_scan_endpoint_invokable(client):
    # 被动扫描对 mock URL 可能 0 命中，但端点应可正常调用、返回 report 结构
    r = client.post("/api/ai-sec/report/scan", json={
        "url": "http://127.0.0.1:5000/chat/<lab>",
        "target_type": "llm_app",
        "strategy": "passive",
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert "scan_id" in body
    assert "report_markdown" in body
    assert "OWASP LLM Top 10" in body["report_markdown"]


def test_metrics_summary(client):
    r = client.post("/api/ai-sec/metrics/summary", json=[
        {"total": 10, "success": 3, "refusals": 1, "leaks": 2, "shield_blocked": 4, "shield_total": 5},
        {"total": 10, "success": 2, "refusals": 3, "leaks": 1, "shield_blocked": 5, "shield_total": 5},
    ])
    assert r.status_code == 200, r.text
    m = r.json()
    assert m["total_attacks"] == 20
    assert m["successful_attacks"] == 5
    assert abs(m["asr"] - 0.25) < 1e-6
    assert abs(m["refusal_rate"] - 0.20) < 1e-6
    assert abs(m["leak_rate"] - 0.15) < 1e-6
    assert abs(m["shield_block_rate"] - 0.90) < 1e-6


def test_report_not_found(client):
    r = client.get("/api/ai-sec/report/NONEXIST")
    assert r.status_code == 404


def test_auth_required_when_key_set(monkeypatch):
    """启用 JIANWEI_API_KEY 后，无/错误 X-API-Key 应 401，正确则 200。"""
    import os
    monkeypatch.setenv("JIANWEI_API_KEY", "topsecret")
    from web.api import create_app
    from fastapi.testclient import TestClient
    app = create_app()
    c = TestClient(app)

    # 1) 无 key -> 401
    r = c.post("/api/ai-sec/report/from-findings", json={
        "target_url": "http://t", "findings": SAMPLE_FINDINGS,
    })
    assert r.status_code == 401

    # 2) 错误 key -> 401
    r = c.post("/api/ai-sec/report/from-findings", json={
        "target_url": "http://t", "findings": SAMPLE_FINDINGS,
    }, headers={"X-API-Key": "wrong"})
    assert r.status_code == 401

    # 3) 正确 key -> 200
    r = c.post("/api/ai-sec/report/from-findings", json={
        "target_url": "http://t", "findings": SAMPLE_FINDINGS,
    }, headers={"X-API-Key": "topsecret"})
    assert r.status_code == 200, r.text
    assert "scan_id" in r.json()


def test_auth_open_when_no_key(client):
    """未设 JIANWEI_API_KEY 时，默认开放（便于本地开发）。"""
    r = client.post("/api/ai-sec/report/from-findings", json={
        "target_url": "http://t", "findings": SAMPLE_FINDINGS,
    })
    assert r.status_code == 200


def test_report_store_pluggable():
    """可插拔存储：内存后端 put/get/exists 闭环。"""
    from web.api.report_store import MemoryReportStore
    s = MemoryReportStore()
    assert not s.exists("x")
    s.put("x", {"k": 1})
    assert s.exists("x")
    assert s.get("x")["k"] == 1

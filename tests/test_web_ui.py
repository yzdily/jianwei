"""§13 平台 UI 前端冒烟测试 —— GET / 与 /static 与基准摘要端点。"""
from __future__ import annotations

from fastapi.testclient import TestClient

from web.api import create_app

client = TestClient(create_app())


def test_index_served():
    r = client.get("/")
    assert r.status_code == 200
    assert "鉴微" in r.text
    assert "扫描发起" in r.text  # 侧栏导航存在


def test_static_index_reachable():
    r = client.get("/static/index.html")
    assert r.status_code == 200
    assert "OWASP LLM Top 10" in r.text or "鉴微" in r.text


def test_benchmark_summary():
    r = client.get("/api/ai-sec/benchmark/summary")
    assert r.status_code == 200
    d = r.json()
    assert "total" in d
    assert d["recall"] == 1.0  # golden 基线 100% 召回
    assert "per_class" in d


def test_report_404_on_missing():
    r = client.get("/api/ai-sec/report/NONEXIST")
    assert r.status_code == 404

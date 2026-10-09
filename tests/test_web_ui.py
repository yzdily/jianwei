"""§13 平台 UI 前端冒烟测试 —— GET / 与 /static 与基准摘要端点。"""
from __future__ import annotations

from fastapi.testclient import TestClient

from web.api import create_app

client = TestClient(create_app())


def test_index_served():
    r = client.get("/")
    assert r.status_code == 200
    assert "鉴微" in r.text
    # 导航标签改由各视图模块渲染（单一事实源），外壳只提供挂载点
    assert "/static/js/app.js" in r.text
    assert 'id="side-nav"' in r.text


def test_nav_label_lives_in_view_module():
    """「扫描发起 / 双轴扫描」语义存在于 01 视图模块（导航的事实源）。"""
    r = client.get("/static/js/views/scan.js")
    assert r.status_code == 200
    assert "双轴扫描" in r.text
    assert "扫描发起" in r.text


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

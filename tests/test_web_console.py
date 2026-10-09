"""统一控制台契约测试 —— 前端资源可达性 + platform info（运行态脱敏）。

上传契约由 `tests/test_web_upload_e2e.py` 覆盖：2026-10-09 收敛后两者指向同一条链路
（主应用 → skill_scan_api → core.handle_upload），此处不再重复断言上传行为。
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from web.api import create_app

client = TestClient(create_app())

CSS_FILES = ["tokens.css", "shell.css", "components.css"]
JS_FILES = [
    "api.js",
    "ui.js",
    "app.js",
    "views/scan.js",
    "views/skill.js",
    "views/agent.js",
    "views/report.js",
    "views/bench.js",
    "views/metrics.js",
    "views/health.js",
    "views/system.js",
    "views/rbac.js",
]


def test_console_assets_reachable():
    """设计 token 与各视图模块必须可被浏览器加载（拆分后任一路径写错都会 404）。"""
    for name in CSS_FILES:
        r = client.get(f"/static/css/{name}")
        assert r.status_code == 200, f"css 缺失: {name}"
    for name in JS_FILES:
        r = client.get(f"/static/js/{name}")
        assert r.status_code == 200, f"js 缺失: {name}"


def test_index_has_no_external_cdn():
    """安全产品需内网/离线可用：外壳不得引用外部 CDN 资源。"""
    html = client.get("/").text
    assert "https://fonts.googleapis.com" not in html
    assert "http://" not in html
    assert "cdn." not in html


def test_index_wires_shell_ids():
    """路由与用户卡依赖的挂载点必须存在，否则前端静默失效。"""
    html = client.get("/").text
    for hook in ['id="side-nav"', 'id="content"', 'id="user-card"', 'id="m-mask"']:
        assert hook in html, f"缺少挂载点: {hook}"


def test_platform_info_is_redacted():
    """运行态接口只回布尔与计数，绝不回传密钥值。"""
    r = client.get("/api/platform/info")
    assert r.status_code == 200
    d = r.json()
    for key in ("title", "version", "routes", "auth_enabled", "llm_key_present", "python"):
        assert key in d, f"缺字段: {key}"
    assert isinstance(d["auth_enabled"], bool)
    assert isinstance(d["llm_key_present"], bool)
    # 路由数必须覆盖全部子路由（回归：FastAPI 新版 _IncludedRouter 曾导致只数到 7）
    assert d["routes"] >= 15, f"路由统计疑似漏掉子路由: {d['routes']}"

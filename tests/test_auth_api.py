"""多用户会话鉴权（方案 C）契约测试。

覆盖：dev 放行（保住既有 237 契约） / 多用户登录 / 401 / 403 角色隔离 / 服务密钥兼容。
设计见 818/多用户鉴权设计_2026-10-09.md。
"""
from __future__ import annotations

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from web.api import create_app, auth as auth_mod


def _build(monkeypatch, **env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    auth_mod._USERS.clear()
    auth_mod._SESSIONS.clear()
    auth_mod._seed_admin()
    return TestClient(create_app())


@pytest.fixture(autouse=True)
def _isolate():
    """测试间隔离：清空内存用户/会话，避免本模块污染其它测试模块。"""
    yield
    auth_mod._USERS.clear()
    auth_mod._SESSIONS.clear()


@pytest.fixture
def dev_client():
    # 不设任何鉴权开关 -> 开发模式全放行
    auth_mod._USERS.clear()
    auth_mod._SESSIONS.clear()
    return TestClient(create_app())


def test_dev_mode_passthrough(dev_client):
    """默认未设开关：读写接口均放行（既有 237 契约依赖此项）。"""
    assert dev_client.get("/api/rbac/overview").status_code == 200
    r = dev_client.post("/api/rbac/roles", json={"name": "x", "permissions": ["report.read"]})
    assert r.status_code == 201


def test_login_and_session(monkeypatch):
    c = _build(monkeypatch, JIANWEI_ADMIN_PASSWORD="s3cret")
    r = c.post("/api/auth/login", json={"username": "admin", "password": "s3cret"})
    assert r.status_code == 200
    token = r.json()["token"]

    me = c.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert "rbac.manage" in me.json()["permissions"]  # 管理员为 superuser

    # 受保护写接口无 token -> 401
    assert c.post("/api/rbac/roles", json={"name": "x", "permissions": ["report.read"]}).status_code == 401
    # 带 token -> 201
    r = c.post(
        "/api/rbac/roles",
        json={"name": "x", "permissions": ["report.read"]},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 201


def test_wrong_password(monkeypatch):
    c = _build(monkeypatch, JIANWEI_ADMIN_PASSWORD="s3cret")
    r = c.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
    assert r.status_code == 401


def test_role_isolation(monkeypatch):
    """研究员（role-researcher，无 rbac.manage）调 rbac.manage 接口应 403。"""
    c = _build(monkeypatch, JIANWEI_ADMIN_PASSWORD="s3cret")
    auth_mod._USERS["researcher"] = {
        "username": "researcher",
        "name": "研究员",
        "password_hash": auth_mod.hash_password("rpw"),
        "role_ids": ["role-researcher"],
        "superuser": False,
        "disabled": False,
    }
    tok = c.post("/api/auth/login", json={"username": "researcher", "password": "rpw"}).json()["token"]
    h = {"Authorization": f"Bearer {tok}"}

    # 登录态可读 rbac 概览（仅需登录）
    assert c.get("/api/rbac/overview", headers=h).status_code == 200
    # rbac.manage 不在研究员权限内 -> 403
    r = c.post("/api/rbac/roles", json={"name": "y", "permissions": ["report.read"]}, headers=h)
    assert r.status_code == 403


def test_service_key_still_works(monkeypatch):
    """服务密钥（JIANWEI_API_KEY）仍应全权限通过；错误密钥 401。"""
    c = _build(monkeypatch, JIANWEI_ADMIN_PASSWORD="s3cret", JIANWEI_API_KEY="svc")
    assert (
        c.post("/api/rbac/roles", json={"name": "z", "permissions": ["report.read"]}, headers={"X-API-Key": "svc"}).status_code
        == 201
    )
    assert (
        c.post("/api/rbac/roles", json={"name": "w", "permissions": ["report.read"]}, headers={"X-API-Key": "bad"}).status_code
        == 401
    )


def test_platform_info_reports_login_enabled(monkeypatch):
    c = _build(monkeypatch, JIANWEI_ADMIN_PASSWORD="s3cret")
    d = c.get("/api/platform/info").json()
    assert d["auth_enabled"] is True
    assert d["login_enabled"] is True

"""权限管理（RBAC）API 契约测试。

重点验证的是**引用完整性**与**白名单**这两类容易在实现里漏掉的规则：
- 权限 id 必须命中目录，否则写入的是「永远不生效的权限」；
- 被引用的角色/用户组不可删，否则权限会静默失效；
- 内置账号不可删，否则可能把自己锁在门外。
"""
from __future__ import annotations

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from web.api import create_app  # noqa: E402
from web.api.rbac_api import reset_store  # noqa: E402


@pytest.fixture
def client():
    reset_store()
    with TestClient(create_app()) as c:
        yield c
    reset_store()


def test_overview_shape(client):
    d = client.get("/api/rbac/overview").json()
    assert {p["id"] for p in d["permissions"]} >= {"scan.run", "skill.upload", "digpool.run"}
    assert d["users"] and d["groups"] and d["roles"]


def test_create_role_rejects_unknown_permission(client):
    r = client.post("/api/rbac/roles", json={"name": "幽灵角色", "permissions": ["do.anything"]})
    assert r.status_code == 422
    assert "未知权限 id" in r.json()["detail"]


def test_role_referenced_by_group_cannot_be_deleted(client):
    role = client.post("/api/rbac/roles", json={"name": "临时角色", "permissions": ["report.read"]}).json()
    group = client.post("/api/rbac/groups", json={"name": "临时组", "roles": [role["id"]]}).json()

    blocked = client.delete(f"/api/rbac/roles/{role['id']}")
    assert blocked.status_code == 409
    assert "引用" in blocked.json()["detail"]

    assert client.delete(f"/api/rbac/groups/{group['id']}").status_code == 204
    assert client.delete(f"/api/rbac/roles/{role['id']}").status_code == 204


def test_group_with_members_cannot_be_deleted(client):
    blocked = client.delete("/api/rbac/groups/group-rd")  # 默认数据里 admin 在该组
    assert blocked.status_code == 409
    assert "属于该组" in blocked.json()["detail"]


def test_user_create_validates_references(client):
    assert client.post("/api/rbac/users", json={"name": "张三", "groups": ["group-nope"]}).status_code == 422
    assert client.post("/api/rbac/users", json={"name": "张三", "roles": ["role-nope"]}).status_code == 422

    created = client.post("/api/rbac/users", json={"name": "张三", "groups": ["group-rd"]})
    assert created.status_code == 201
    uid = created.json()["id"]
    assert client.delete(f"/api/rbac/users/{uid}").status_code == 204


def test_builtin_admin_cannot_be_deleted(client):
    r = client.delete("/api/rbac/users/user-admin")
    assert r.status_code == 409
    assert "内置账号" in r.json()["detail"]


def test_delete_unknown_returns_404(client):
    assert client.delete("/api/rbac/users/user-none").status_code == 404
    assert client.delete("/api/rbac/roles/role-none").status_code == 404
    assert client.delete("/api/rbac/groups/group-none").status_code == 404

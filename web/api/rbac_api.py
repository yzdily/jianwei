"""权限管理（RBAC）API —— 通用功能后端。

收敛背景：控制台「通用功能 → 权限管理」在 Demo 里只有界面（子账号 / 用户组 / 角色三个 Tab），
没有后端支撑。本模块补上真实实现，权限 id 与既有接口对齐（`scan.run` / `skill.upload`
/ `digpool.run` / `report.read` …）。

存储：进程内内存（与 `report_store`、skill `_STORE` 保持一致的模式）。
      生产应换 Redis/DB 并接入统一身份源（LDAP/OIDC），此处不引入额外依赖。

端点（统一前缀 /api/rbac）：
    GET    /overview              权限目录 + 全部主体（供 UI 一次拉取）
    GET    /users                 子账号列表
    POST   /users                 新建子账号
    DELETE /users/{user_id}       删除子账号
    GET    /groups                用户组列表
    POST   /groups                新建用户组
    DELETE /groups/{group_id}     删除用户组
    GET    /roles                 角色列表
    POST   /roles                 新建角色
    DELETE /roles/{role_id}       删除角色
"""
from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from core.log import get_logger

from .auth import RequireAuth

log = get_logger("web.api.rbac")

router = APIRouter(prefix="/api/rbac", tags=["rbac"])

# 权限目录：与其它路由的写接口一一对应，避免出现「界面能勾、后端不认」的空权限
PERMISSIONS: list[dict[str, str]] = [
    {"id": "scan.run", "name": "发起双轴扫描", "group": "扫描"},
    {"id": "scan.read", "name": "查看扫描结果", "group": "扫描"},
    {"id": "skill.upload", "name": "上传 Skill 扫描", "group": "供应链"},
    {"id": "digpool.run", "name": "运行智能体工作台", "group": "智能体"},
    {"id": "report.read", "name": "查看报告", "group": "报告"},
    {"id": "report.export", "name": "导出报告 / SARIF", "group": "报告"},
    {"id": "rbac.manage", "name": "管理权限与账号", "group": "管理"},
]

_VALID_PERMS = {p["id"] for p in PERMISSIONS}

# 内存存储（生产换 DB）
_USERS: dict[str, dict[str, Any]] = {}
_GROUPS: dict[str, dict[str, Any]] = {}
_ROLES: dict[str, dict[str, Any]] = {}


def _seed() -> None:
    """首次导入时种入一组可解释的默认数据，便于零配置演示。"""
    if _USERS or _GROUPS or _ROLES:
        return
    _ROLES["role-researcher"] = {
        "id": "role-researcher", "name": "研究员",
        "desc": "双轴扫描 · Skill 上传 · 智能体编排",
        "permissions": ["scan.run", "scan.read", "skill.upload", "digpool.run", "report.read"],
    }
    _ROLES["role-auditor"] = {
        "id": "role-auditor", "name": "审核员",
        "desc": "只读审计 · 报告导出",
        "permissions": ["scan.read", "report.read", "report.export"],
    }
    _GROUPS["group-rd"] = {
        "id": "group-rd", "name": "研发组",
        "desc": "智能体工作台 · Skill 编排",
        "roles": ["role-researcher"], "owner": "admin",
    }
    _GROUPS["group-sec"] = {
        "id": "group-sec", "name": "安全组",
        "desc": "双轴扫描 · 报告处置",
        "roles": ["role-researcher", "role-auditor"], "owner": "admin",
    }
    _USERS["user-admin"] = {
        "id": "user-admin", "name": "研究员", "email": "researcher@jwt.local",
        "groups": ["group-rd", "group-sec"], "roles": ["role-researcher"], "disabled": False,
    }


_seed()


# ----------------------------------------------------------------------------
# 请求模型
# ----------------------------------------------------------------------------
class UserIn(BaseModel):
    """新建子账号。"""
    name: str = Field(..., min_length=1, description="显示名")
    email: str = Field(default="", description="邮箱（本地开发模式仅作展示）")
    groups: list[str] = Field(default_factory=list, description="所属用户组 id")
    roles: list[str] = Field(default_factory=list, description="直接授予的角色 id")


class GroupIn(BaseModel):
    """新建用户组。"""
    name: str = Field(..., min_length=1, description="组名")
    desc: str = Field(default="", description="用途说明")
    roles: list[str] = Field(default_factory=list, description="组内角色 id")


class RoleIn(BaseModel):
    """新建角色。"""
    name: str = Field(..., min_length=1, description="角色名")
    desc: str = Field(default="", description="职责说明")
    permissions: list[str] = Field(default_factory=list, description="权限 id 列表")


def _check_perm_ids(ids: list[str]) -> None:
    """拒绝未知权限 id —— 权限目录是白名单，避免写进永远不生效的权限。"""
    unknown = [i for i in ids if i not in _VALID_PERMS]
    if unknown:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"未知权限 id：{', '.join(unknown)}",
        )


def reset_store() -> None:
    """清空并重新种入默认数据（测试与「恢复默认」用）。"""
    _USERS.clear()
    _GROUPS.clear()
    _ROLES.clear()
    _seed()


# ----------------------------------------------------------------------------
# 端点
# ----------------------------------------------------------------------------
@router.get("/overview")
async def overview():
    """一次返回权限目录与全部主体，避免 UI 发三个请求。"""
    return {
        "permissions": PERMISSIONS,
        "users": sorted(_USERS.values(), key=lambda u: u["name"]),
        "groups": sorted(_GROUPS.values(), key=lambda g: g["name"]),
        "roles": sorted(_ROLES.values(), key=lambda r: r["name"]),
    }


@router.get("/users")
async def list_users():
    return sorted(_USERS.values(), key=lambda u: u["name"])


@router.post("/users", status_code=status.HTTP_201_CREATED)
async def create_user(payload: UserIn, _auth: bool = Depends(RequireAuth("rbac.manage"))):
    """新建子账号。组/角色 id 必须已存在，避免指向悬空主体。"""
    for gid in payload.groups:
        if gid not in _GROUPS:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"用户组不存在：{gid}")
    for rid in payload.roles:
        if rid not in _ROLES:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"角色不存在：{rid}")

    user_id = f"user-{uuid.uuid4().hex[:8]}"
    _USERS[user_id] = {
        "id": user_id,
        "name": payload.name,
        "email": payload.email,
        "groups": payload.groups,
        "roles": payload.roles,
        "disabled": False,
    }
    log.info(f"rbac: user created {user_id}")
    return _USERS[user_id]


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(user_id: str, _auth: bool = Depends(RequireAuth("rbac.manage"))):
    """删除子账号（内置 admin 账号受保护，防止把自己锁死）。"""
    if user_id == "user-admin":
        raise HTTPException(status.HTTP_409_CONFLICT, "内置账号不可删除")
    if _USERS.pop(user_id, None) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "子账号不存在")
    return None


@router.get("/groups")
async def list_groups():
    return sorted(_GROUPS.values(), key=lambda g: g["name"])


@router.post("/groups", status_code=status.HTTP_201_CREATED)
async def create_group(payload: GroupIn, _auth: bool = Depends(RequireAuth("rbac.manage"))):
    for rid in payload.roles:
        if rid not in _ROLES:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"角色不存在：{rid}")
    group_id = f"group-{uuid.uuid4().hex[:8]}"
    _GROUPS[group_id] = {
        "id": group_id,
        "name": payload.name,
        "desc": payload.desc,
        "roles": payload.roles,
        "owner": "admin",
    }
    return _GROUPS[group_id]


@router.delete("/groups/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_group(group_id: str, _auth: bool = Depends(RequireAuth("rbac.manage"))):
    """删除用户组；若仍有成员引用则拒绝（保持引用完整性）。"""
    members = [u["id"] for u in _USERS.values() if group_id in u.get("groups", [])]
    if members:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"仍有 {len(members)} 个账号属于该组，请先移出：" + ", ".join(members),
        )
    if _GROUPS.pop(group_id, None) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "用户组不存在")
    return None


@router.get("/roles")
async def list_roles():
    return sorted(_ROLES.values(), key=lambda r: r["name"])


@router.post("/roles", status_code=status.HTTP_201_CREATED)
async def create_role(payload: RoleIn, _auth: bool = Depends(RequireAuth("rbac.manage"))):
    _check_perm_ids(payload.permissions)
    role_id = f"role-{uuid.uuid4().hex[:8]}"
    _ROLES[role_id] = {
        "id": role_id,
        "name": payload.name,
        "desc": payload.desc,
        "permissions": payload.permissions,
    }
    return _ROLES[role_id]


@router.delete("/roles/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_role(role_id: str, _auth: bool = Depends(RequireAuth("rbac.manage"))):
    """删除角色；被用户组引用时拒绝，避免组权限静默失效。"""
    holders = [g["id"] for g in _GROUPS.values() if role_id in g.get("roles", [])]
    if holders:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"角色仍被 {len(holders)} 个用户组引用：请先解绑 " + ", ".join(holders),
        )
    if _ROLES.pop(role_id, None) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "角色不存在")
    return None

"""多用户会话鉴权（最小可用版，方案见 818/多用户鉴权设计_2026-10-09.md）。

认证 (Authentication)：用户名 + 密码（scrypt 哈希）登录，签发内存会话 token。
授权 (Authorization)：会话用户按 RBAC 角色 / 权限校验（接 rbac_api 的权限目录）。

向后兼容（关键）：
- 未设 JIANWEI_API_KEY 且未设 JIANWEI_ADMIN_PASSWORD -> 开发模式，全部放行（零密钥可跑）。
- 仅设 JIANWEI_API_KEY -> 服务密钥模式：请求须带正确 X-API-Key（全权限，便于 CI / 程序调用）。
- 仅设 JIANWEI_ADMIN_PASSWORD -> 多用户模式：须先登录拿会话 token（按角色校验权限）。
- 两者都设 -> 任一满足即可。

零依赖：密码哈希用标准库 hashlib.scrypt（内存硬 KDF，强度等同 / 优于 bcrypt，且内网离线可用）。
"""
from __future__ import annotations

import os
import secrets
import hashlib
import time
from typing import Any, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field

from core.log import get_logger

log = get_logger("web.api.auth")

router = APIRouter(prefix="/api/auth", tags=["auth"])

# ---- 配置 ----
ADMIN_PASSWORD_ENV = "JIANWEI_ADMIN_PASSWORD"
API_KEY_ENV = "JIANWEI_API_KEY"
SESSION_TTL = 60 * 60 * 8  # 8 小时

# ---- 存储（进程内内存，生产换 DB；与 rbac / report 一致的内存态模式）----
_USERS: dict[str, dict[str, Any]] = {}        # username -> {name, password_hash(salt$hash), role_ids, superuser, disabled}
_SESSIONS: dict[str, dict[str, Any]] = {}     # token -> {username, expires}

# 服务账号哨兵：代表"持有有效 X-API-Key"的调用方，拥有全权限（跳过具体权限校验）。
_SERVICE_USER: dict[str, Any] = {"username": "service", "service": True, "permissions": ["*"]}


# ----------------------------------------------------------------------------
# 密码哈希（统一收口，便于将来换 bcrypt）
# ----------------------------------------------------------------------------
def hash_password(password: str) -> str:
    """返回 'salt_hex$hash_hex'，salt 每用户随机。"""
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return salt.hex() + "$" + dk.hex()


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, hash_hex = stored.split("$", 1)
        dk = hashlib.scrypt(
            password.encode("utf-8"), salt=bytes.fromhex(salt_hex), n=2**14, r=8, p=1, dklen=32
        )
        return secrets.compare_digest(dk.hex(), hash_hex)
    except Exception:  # noqa: BLE001 - 任何异常都视为校验失败，绝不抛出
        return False


# ----------------------------------------------------------------------------
# 种子管理员（仅当 JIANWEI_ADMIN_PASSWORD 设置时）
# ----------------------------------------------------------------------------
def _seed_admin() -> None:
    """仅当部署设定 JIANWEI_ADMIN_PASSWORD 时种子化管理员账号。

    绝不生成默认弱口令；未设定则 dev 模式不种子、不需登录。
    """
    if "admin" in _USERS:
        return
    pw = os.getenv(ADMIN_PASSWORD_ENV)
    if not pw:
        return
    _USERS["admin"] = {
        "username": "admin",
        "name": "系统管理员",
        "password_hash": hash_password(pw),
        "role_ids": ["role-researcher", "role-auditor"],
        "superuser": True,
        "disabled": False,
    }
    log.info("auth: 已用 JIANWEI_ADMIN_PASSWORD 初始化管理员账号 (admin)")


_seed_admin()


def _auth_enabled() -> bool:
    """多用户登录是否启用——由配置（环境变量）驱动，而非内存状态。

    这样即便内存里残留 admin 账号（如测试进程复用），未设环境变量时仍为开发模式全放行，
    避免跨测试互相污染。生产环境进程启动时环境变量已就绪，admin 在导入时即被种子化。
    """
    return bool(os.getenv(ADMIN_PASSWORD_ENV))


# ----------------------------------------------------------------------------
# 权限解析（懒加载 rbac_api，避免循环导入）
# ----------------------------------------------------------------------------
def resolve_user_permissions(user: dict) -> set[str]:
    """聚合用户全部角色的权限；superuser 直接拿全部权限目录。"""
    if user.get("superuser"):
        from . import rbac_api

        return {p["id"] for p in rbac_api.PERMISSIONS}
    role_ids = user.get("role_ids", [])
    if not role_ids:
        return set()
    from . import rbac_api

    perms: set[str] = set()
    for rid in role_ids:
        role = rbac_api._ROLES.get(rid)
        if role:
            perms.update(role.get("permissions", []))
    return perms


# ----------------------------------------------------------------------------
# 会话解析
# ----------------------------------------------------------------------------
def _parse_bearer(authorization: Optional[str]) -> Optional[str]:
    if not authorization:
        return None
    parts = authorization.split(" ", 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return None


def _session_user(authorization: Optional[str]) -> Optional[dict]:
    token = _parse_bearer(authorization)
    if not token:
        return None
    sess = _SESSIONS.get(token)
    if not sess or sess["expires"] < time.time():
        return None
    return _USERS.get(sess["username"])


def _authorize(authorization: Optional[str], x_api_key: Optional[str], perm: Optional[str]) -> Optional[dict]:
    """统一鉴权：返回用户对象（含服务账号哨兵），未认证/未授权则抛异常。"""
    # 1) 会话用户（多用户模式）
    user = _session_user(authorization)
    if user is not None:
        if perm and perm not in resolve_user_permissions(user):
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"权限不足：需要 {perm}")
        return user

    # 2) 服务密钥（既有模式，全权限，便于 CI / 程序调用）
    expected = os.getenv(API_KEY_ENV)
    if expected and x_api_key == expected:
        return _SERVICE_USER

    # 3) 任一鉴权开关已开启，但凭证缺失 / 无效 -> 401
    if expected or _auth_enabled():
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "未认证：请先登录或提供 X-API-Key")

    # 4) 开发模式：全部放行
    return None


class RequireAuth:
    """可携带权限参数的鉴权依赖。

    用法：
        Depends(require_auth)                  # 仅要求已登录（或有效服务密钥）
        Depends(RequireAuth("rbac.manage"))    # 额外要求该权限
    """

    def __init__(self, perm: Optional[str] = None) -> None:
        self.perm = perm

    def __call__(
        self,
        authorization: Optional[str] = Header(default=None, alias="Authorization"),
        x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    ) -> Optional[dict]:
        return _authorize(authorization, x_api_key, self.perm)


require_auth = RequireAuth()


# ----------------------------------------------------------------------------
# 端点（login / logout / me 保持公开，不挂路由级依赖）
# ----------------------------------------------------------------------------
class LoginIn(BaseModel):
    username: str = Field(..., min_length=1, description="用户名")
    password: str = Field(..., min_length=1, description="密码")


@router.post("/login")
async def login(payload: LoginIn):
    """用户名 + 密码登录，签发会话 token。"""
    user = _USERS.get(payload.username)
    if not user or user.get("disabled") or not verify_password(payload.password, user["password_hash"]):
        # 统一返回模糊错误，避免用户枚举
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "用户名或密码错误")
    token = secrets.token_urlsafe(32)
    _SESSIONS[token] = {"username": user["username"], "expires": time.time() + SESSION_TTL}
    log.info("auth: user logged in %s", user["username"])
    return {
        "token": token,
        "user": {
            "username": user["username"],
            "name": user.get("name"),
            "roles": user.get("role_ids", []),
            "permissions": sorted(resolve_user_permissions(user)),
        },
    }


def _current_user(authorization: Optional[str] = Header(default=None, alias="Authorization")) -> Optional[dict]:
    return _session_user(authorization)


@router.get("/me")
async def me(user: Optional[dict] = Depends(_current_user)):
    """返回当前登录用户；未登录 / 会话过期 -> 401。"""
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "未登录或会话已过期")
    return {
        "username": user["username"],
        "name": user.get("name"),
        "roles": user.get("role_ids", []),
        "permissions": sorted(resolve_user_permissions(user)),
    }


@router.post("/logout")
async def logout(authorization: Optional[str] = Header(default=None, alias="Authorization")):
    """注销当前会话（客户端也应丢弃 token）。"""
    token = _parse_bearer(authorization)
    if token and token in _SESSIONS:
        _SESSIONS.pop(token, None)
    return {"ok": True}

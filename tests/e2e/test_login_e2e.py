"""登录页 E2E —— 多用户鉴权闸门（Playwright 驱动真实浏览器）。

与 test_console_e2e.py 的关键区别：
    test_console_e2e 跑在 **dev 模式**（两开关都不设，全部放行），
    本文件必须跑在 **多用户模式**（启动时设 JIANWEI_ADMIN_PASSWORD），
    否则登录闸门根本不会弹出——也就验收不到任何东西。

覆盖链路：
    ① 多用户模式下进站 -> 弹出登录遮罩（而不是直接进控制台）
    ② 错密码 -> 就地报错，且仍被拦在闸门外
    ③ 对密码 -> 遮罩真正关闭、右上用户卡显示 admin、受保护视图能拉到数据
       （证明 token 确实被带上了请求，而非只是前端自己以为登录了）
    ④ 退出登录 -> 遮罩重新弹出、sessionStorage 里的 token 被清除

运行（**单独跑**，默认被 pytest.ini 的 addopts 排除）：
    pytest -m e2e tests/e2e/test_login_e2e.py
为什么必须与纯接口用例分开：Playwright 同步 API 会占用进程事件循环，与
pytest-asyncio 同进程会互相干扰。
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

pytestmark = pytest.mark.e2e

ROOT = Path(__file__).resolve().parents[2]

# 仅测试用口令；真实部署由环境变量注入，绝不写入仓库。
ADMIN_USER = "admin"
ADMIN_PASSWORD = "E2E-strong-pass-2026"


# ---------------------------------------------------------------- 基础设施
def _free_port() -> int:
    """让内核分配空闲端口，避免与开发者本地服务撞车。"""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_health(url: str, timeout: float = 30.0) -> bool:
    """轮询 /health 直到就绪（uvicorn 冷启动 + 引擎 import 可能较慢）。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url + "/health", timeout=1) as resp:
                if resp.status == 200:
                    return True
        except (urllib.error.URLError, OSError):
            time.sleep(0.3)
    return False


def _tail(path: Path, limit: int = 2000) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[-limit:]
    except OSError:
        return "<无日志>"


@pytest.fixture(scope="session")
def auth_base_url(tmp_path_factory):
    """起一个 **开启多用户鉴权** 的 uvicorn 子进程。

    与 conftest 的 base_url（dev 模式）互不影响：不同随机端口、不同进程、
    各自独立的 JIANWEI_ADMIN_PASSWORD 环境变量。

    注意：子进程输出必须重定向到文件，不能接 subprocess.PIPE——
    uvicorn 每请求打日志，管道缓冲区写满后子进程会阻塞在 write() 导致服务假死。
    """
    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    log_path = tmp_path_factory.mktemp("e2e-auth") / "uvicorn.log"
    env = dict(os.environ, JIANWEI_ADMIN_PASSWORD=ADMIN_PASSWORD)
    with open(log_path, "wb") as log:
        proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "web.api:app", "--host", "127.0.0.1", "--port", str(port)],
            cwd=str(ROOT),
            stdout=log,
            stderr=subprocess.STDOUT,
            env=env,
        )
        try:
            if not _wait_health(url):
                pytest.fail(f"uvicorn（多用户模式）未在超时内就绪：{url}\n{_tail(log_path)}")
            yield url
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()


# ---------------------------------------------------------------- 动作封装
def _open_login(pg, base_url: str):
    """进站并等待登录遮罩出现（多用户模式下闸门必然弹出）。"""
    pg.goto(base_url, wait_until="load")
    pg.wait_for_selector("[data-testid=login-mask]:visible", timeout=15_000)
    return pg.locator("[data-testid=login-mask]")


def _submit(pg, password: str) -> None:
    """填表并提交（前置：登录遮罩已出现）。"""
    pg.fill("[data-testid=login-user]", ADMIN_USER)
    pg.fill("[data-testid=login-pass]", password)
    pg.click("[data-testid=login-submit]")


# ---------------------------------------------------------------- ① 闸门出现
def test_login_gate_appears_in_multiuser_mode(page, auth_base_url):
    """多用户模式下：进站必须先过登录闸门，而不是裸奔进控制台。"""
    pg = page
    mask = _open_login(pg, auth_base_url)

    assert mask.is_visible()
    assert pg.locator("[data-testid=login-user]").is_visible()
    assert pg.locator("[data-testid=login-pass]").is_visible()
    assert pg.locator("[data-testid=login-submit]").is_visible()
    assert pg.js_errors == [], f"页面出现 JS 异常：{pg.js_errors}"


# ---------------------------------------------------------------- ② 错密码
def test_wrong_password_is_rejected(page, auth_base_url):
    """错密码：就地给出错误提示，且遮罩不关闭（仍被拦在门外）。"""
    pg = page
    _open_login(pg, auth_base_url)
    _submit(pg, "definitely-wrong-password")

    err = pg.locator("[data-testid=login-error]")
    err.wait_for(state="visible", timeout=10_000)
    # 等文案真正写入（后端 401 -> "用户名或密码错误"）
    pg.wait_for_function(
        "() => (document.querySelector('[data-testid=login-error]').textContent || '').trim().length > 0",
        timeout=10_000,
    )
    text = err.inner_text()
    assert ("错误" in text) or ("失败" in text), f"错误提示不符预期：{text!r}"

    # 关键：没有被放进控制台
    assert pg.locator("[data-testid=login-mask]").is_visible()
    assert pg.evaluate("() => sessionStorage.getItem('jw_token')") is None
    assert pg.js_errors == []


# ---------------------------------------------------------------- ③ 对密码
def test_correct_password_enters_console(page, auth_base_url):
    """对密码：遮罩真正关闭 + 用户卡显示 admin + 受保护视图能取到数据。

    最后一条是核心——它证明「token 确实被带进了请求」，而不是前端自说自话。
    """
    pg = page
    _open_login(pg, auth_base_url)
    _submit(pg, ADMIN_PASSWORD)

    # 遮罩必须真正不可见（不只是挂了 hidden 属性）
    pg.locator("[data-testid=login-mask]").wait_for(state="hidden", timeout=15_000)

    # 右上用户卡显示真实登录用户
    pg.wait_for_function(
        "() => { const b = document.querySelector('#user-card b'); "
        "return !!b && b.textContent.trim() === 'admin'; }",
        timeout=10_000,
    )

    # token 真在生效：切到受保护视图（rbac 路由挂了 RequireAuth），能拉到权限目录
    pg.click("[data-testid=nav-rbac]")
    pg.wait_for_selector("[data-testid=rbac-perms] tbody tr", timeout=15_000)
    assert pg.locator("[data-testid=rbac-perms] tbody tr").count() >= 7
    # 若 token 未生效，这里会再被 401 打回登录页——反向校验遮罩没复现
    assert pg.locator("[data-testid=login-mask]").is_visible() is False
    assert pg.js_errors == []


# ---------------------------------------------------------------- ④ 退出登录
def test_logout_returns_to_login_gate(page, auth_base_url):
    """退出登录：清会话 + 重新弹出登录遮罩。"""
    pg = page
    _open_login(pg, auth_base_url)
    _submit(pg, ADMIN_PASSWORD)
    pg.locator("[data-testid=login-mask]").wait_for(state="hidden", timeout=15_000)

    # 打开右上用户卡菜单 -> 退出登录
    pg.click("[data-testid=user-card]")
    pg.click("#user-menu [data-um=logout]")

    # 遮罩必须重新出现
    pg.locator("[data-testid=login-mask]").wait_for(state="visible", timeout=10_000)
    assert pg.locator("[data-testid=login-mask]").is_visible()
    # token 必须已被清除
    assert pg.evaluate("() => sessionStorage.getItem('jw_token')") is None
    assert pg.js_errors == []

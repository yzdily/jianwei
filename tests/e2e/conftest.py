"""E2E 测试基础设施 —— 本地起 uvicorn + Playwright 驱动真实浏览器。

设计要点：
- **不下载浏览器**：优先用本机已有的 Chrome / Edge（`channel=`），
  都没有才回退到 Playwright 自带 Chromium；全都没有则 `skip` 而非失败。
- **自管服务生命周期**：随机端口起子进程，轮到 `/health` 就绪才开测，退出时 terminate。
- 标记为 `e2e`，可用 `pytest -m "not e2e"` 在纯接口层快速回归时排除。
"""
from __future__ import annotations

import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _free_port() -> int:
    """让内核分配一个空闲端口，避免与开发者本地服务（如 8000/8123）撞车。"""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_health(url: str, timeout: float = 30.0) -> bool:
    """轮询 /health 直到就绪；uvicorn 冷启动 + 引擎 import 可能较慢。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url + "/health", timeout=1) as resp:
                if resp.status == 200:
                    return True
        except (urllib.error.URLError, OSError):
            time.sleep(0.3)
    return False


@pytest.fixture(scope="session")
def base_url(tmp_path_factory):
    """起一个真实的 uvicorn 子进程，产出 base_url，测试结束后回收。

    注意：子进程输出**必须**重定向到文件/DEVNULL，不能接 `subprocess.PIPE`——
    uvicorn 每个请求都打日志，管道缓冲区（约 64KB）写满后子进程会阻塞在 write()，
    服务随即假死（表现为 page.goto 超时）。
    """
    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    log_path = tmp_path_factory.mktemp("e2e") / "uvicorn.log"
    with open(log_path, "wb") as log:
        proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "web.api:app", "--host", "127.0.0.1", "--port", str(port)],
            cwd=str(ROOT),
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            if not _wait_health(url):
                pytest.fail(f"uvicorn 未在超时内就绪：{url}\n{_tail(log_path)}")
            yield url
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()


def _tail(path: Path, limit: int = 2000) -> str:
    """读日志尾部，供启动失败时定位原因。"""
    try:
        return path.read_text(encoding="utf-8", errors="replace")[-limit:]
    except OSError:
        return "<无日志>"


def _launch(pw):
    """按本机已有浏览器依次尝试启动；都不行返回 None（由调用方 skip）。"""
    # channel 优先：免下载，且更贴近用户真实环境
    for kwargs in ({"channel": "chrome"}, {"channel": "msedge"}, {}):
        try:
            return pw.chromium.launch(headless=True, **kwargs)
        except Exception:  # noqa: BLE001 - 逐个候选尝试，失败即下一个
            continue
    return None


@pytest.fixture(scope="session")
def browser():
    pw_api = pytest.importorskip("playwright.sync_api", reason="需要 playwright（pip install playwright）")
    with pw_api.sync_playwright() as pw:
        browser = _launch(pw)
        if browser is None:
            pytest.skip("无可用浏览器：请 `playwright install chromium` 或安装 Chrome / Edge")
        yield browser
        browser.close()


@pytest.fixture
def page(browser):
    """每个用例一个干净页面，并收集 JS 运行时错误供用例断言。"""
    ctx = browser.new_context(viewport={"width": 1440, "height": 900})
    pg = ctx.new_page()
    pg.js_errors = []  # type: ignore[attr-defined]
    pg.on("pageerror", lambda e: pg.js_errors.append(str(e)))
    yield pg
    ctx.close()

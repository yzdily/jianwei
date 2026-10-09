"""F · 零依赖测试路径 —— 保证 MVP 工作台（core/digpool）不因缺第三方依赖而崩。

覆盖：无 yaml/httpx/openai/fastapi 时的导入与运行、StubCore 降级、技能市场、内嵌矩阵兜底。
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class TestRegistryAndMarket:
    def test_builtins_registered(self):
        from core.digpool.tools import get_registry

        names = set(get_registry().names())
        assert {"skill-scan", "llm-top10", "asset-discovery", "sec-shield-check"} <= names

    def test_skill_market_autoregistered(self):
        from core.digpool.tools import get_registry

        names = get_registry().names()
        assert any(n.startswith("skill:") for n in names), "skills_my 的 SKILL.md 应自动登记为 curated 工具"

    def test_skill_tool_runs_stdlib_only(self):
        from core.digpool.tools import get_registry

        skill = next(t for t in get_registry().list() if t.source == "skill" and t.name.startswith("skill:"))
        out = skill.handler({})
        assert out["ok"] is True
        assert "probes" in out["meta"]


class TestBackendDowngrade:
    def test_backend_name(self):
        from core.digpool.core_link import get_core_backend

        assert get_core_backend().backend_name in ("stub", "xuanjian")


class TestLoopMatrixFallback:
    def test_loop_controller_loads_matrix(self):
        from core.digpool.loops.loop_controller import LoopController

        lc = LoopController()
        assert lc.matrix, "LOOP 矩阵（yaml 或内嵌兜底）应非空"

    def test_agent_factory(self):
        from core.digpool.agent import DeterministicAgent, get_agent

        assert isinstance(get_agent(), DeterministicAgent)


class TestZeroDependencyImport:
    """子进程屏蔽第三方依赖，验证 core.digpool 仍可导入并可用（stdlib-only 路径）。"""

    def test_import_and_use_without_third_party(self):
        code = (
            "import sys, builtins\n"
            "_real = builtins.__import__\n"
            "BLOCK = {'yaml','httpx','openai','anthropic','fastapi','uvicorn','starlette','sse_starlette'}\n"
            "def _fake(name, *a, **k):\n"
            "    if name.split('.')[0] in BLOCK:\n"
            "        raise ImportError('blocked(dep-missing simulation): ' + name)\n"
            "    return _real(name, *a, **k)\n"
            "builtins.__import__ = _fake\n"
            "import core.digpool\n"
            "from core.digpool.tools import get_registry\n"
            "from core.digpool.loops.loop_controller import LoopController\n"
            "from core.digpool.core_link import get_core_backend\n"
            "names = get_registry().names()\n"
            "lc = LoopController()\n"
            "print('OK', get_core_backend().backend_name, len(names), len(lc.matrix))\n"
        )
        r = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True, text=True, cwd=str(ROOT),
        )
        assert r.returncode == 0, f"零依赖导入失败:\n{r.stderr}"
        assert r.stdout.startswith("OK"), r.stdout

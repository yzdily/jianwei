"""工作台闭环验证（M1 Planner / M3 Validator / M4 Reporter+Memory）。

覆盖《鉴微优化方案 §5 优化 D》的 DoD：
- `plan` 输出子任务 DAG（RECON→…→REPORT）+ 预算估算；
- `solve` 端到端闭环：plan → execute → verify → report → memory；
- VALIDATE 双重去误报：有证据 → confirmed；合成无证据 → suspect；重复 → rejected；
- 记忆落盘并可 recall（驱动下一次任务）。
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from core.digpool.agent import DeterministicAgent
from core.digpool.agents.planner import PHASES, DeterministicPlanner
from core.digpool.agents.reporter import Reporter
from core.digpool.agents.validator import (
    VERDICT_CONFIRMED,
    VERDICT_REJECTED,
    VERDICT_SUSPECT,
    StubValidator,
)
from core.digpool.loops.loop_controller import Finding
from core.digpool.memory.store import MemoryStore
from core.digpool.session import DigPoolSession, SessionPhase

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = "tests/fixtures/malicious_skill"


# ---------------------------------------------------------------------------
# M1 Planner
# ---------------------------------------------------------------------------

def test_planner_builds_full_dag_with_budget():
    plan = DeterministicPlanner().plan("检测 sqli 注入", target="https://api.example.com")
    assert plan.phases() == list(PHASES)
    assert plan.budget_tokens > 0
    execute = [s for s in plan.subtasks if s.phase == "EXECUTE"][0]
    assert execute.action == "loop"
    assert execute.trigger == "sqli_possible"
    d = plan.to_dict()
    assert d["edges"] and d["subtasks"]
    assert ("t2", "t3") in d["edges"]  # 显式依赖边


def test_planner_local_target_uses_skill_scan():
    plan = DeterministicPlanner().plan("扫一下这个技能包", target=FIXTURE)
    execute = [s for s in plan.subtasks if s.phase == "EXECUTE"][0]
    assert execute.action == "tool"
    assert execute.tool == "skill-scan"


def test_planner_extracts_target_from_goal():
    plan = DeterministicPlanner().plan("帮我测 https://a.example.com 的 ssrf 问题")
    assert plan.target == "https://a.example.com"
    execute = [s for s in plan.subtasks if s.phase == "EXECUTE"][0]
    assert execute.trigger == "ssrf_possible"


# ---------------------------------------------------------------------------
# M3 Validator（双重去误报）
# ---------------------------------------------------------------------------

def _finding(**kw) -> Finding:
    base = dict(id="F1", vuln_type="XSS", severity="high", url="a/x")
    base.update(kw)
    return Finding(**base)


def test_validator_confirms_finding_with_evidence():
    f = _finding(id="F-ok", detail={"payload": "<script>", "snippet": "echo", "file_path": "evil.py", "line": 3})
    res = StubValidator().validate([f])
    assert res[0].verdict == VERDICT_CONFIRMED
    assert res[0].verified is True
    assert StubValidator().confirmed([f]) == [f]


def test_validator_marks_synthetic_finding_suspect():
    # DeterministicAgent 合成 Finding：仅有观测产物、无可复现证据
    f = _finding(
        id="F-synth", vuln_type="Generic", url="https://api.example.com",
        detail={"step": "distinguish", "agent": "deterministic"},
        extracted_artifacts={"observed_step": "distinguish", "agent": "deterministic"},
    )
    res = StubValidator().validate([f])
    assert res[0].verdict == VERDICT_SUSPECT
    assert res[0].verified is False


def test_validator_rejects_duplicate_finding():
    f1 = _finding(id="F1", detail={"payload": "p", "snippet": "s"})
    f2 = _finding(id="F2", detail={"payload": "p", "snippet": "s"})
    res = StubValidator().validate([f1, f2])
    assert res[0].verdict == VERDICT_CONFIRMED
    assert res[1].verdict == VERDICT_REJECTED


def test_validator_rejects_finding_without_location():
    f = _finding(id="F1", url="", detail={"payload": "p"})
    res = StubValidator().validate([f])
    assert res[0].verdict == VERDICT_REJECTED


# ---------------------------------------------------------------------------
# M4 MemoryStore / Reporter
# ---------------------------------------------------------------------------

def test_memory_store_roundtrip_and_recall(tmp_path):
    store = MemoryStore(tmp_path)
    key = store.project_key_for("https://api.example.com/v1/chat")
    assert key == "api.example.com"
    store.save_report(key, "RUN-1", "# report")
    store.save_run(key, {
        "run_id": "RUN-1", "target": "https://api.example.com",
        "vuln_types": ["XSS"], "triggers": ["sqli_possible"], "termination": "confirmed",
    })
    assert store.latest(key)["run_id"] == "RUN-1"
    rec = store.recall(key)
    assert rec["run_count"] == 1
    assert rec["known_vuln_types"] == ["XSS"]
    assert rec["known_triggers"] == ["sqli_possible"]
    assert store.report_path(key, "RUN-1").exists()


def test_memory_project_key_for_local_path(tmp_path):
    store = MemoryStore(tmp_path)
    assert store.project_key_for(FIXTURE) == "malicious_skill"
    assert store.project_key_for(None) == "default"


def test_reporter_builds_expected_sections():
    plan = DeterministicPlanner().plan("检测 sqli", target="https://api.example.com")
    f = _finding(id="F1", detail={"snippet": "s", "file_path": "a.py", "line": 1})
    validation = StubValidator().validate([f])
    md = Reporter().build(
        goal="检测 sqli", target="https://api.example.com", plan=plan,
        executions=[{"subtask": "t3", "action": "loop", "trigger": "sqli_possible",
                     "depth_chain": 3, "termination": "max_depth_reached"}],
        validation=validation, memory_key="api.example.com",
    )
    for section in ("# 鉴微 DigPool 安全测试报告", "## 1. 执行摘要", "## 2. 覆盖矩阵",
                    "## 3. 漏洞详情", "## 4. 疑似与去误报", "## 5. 项目记忆"):
        assert section in md
    assert "XSS" in md


# ---------------------------------------------------------------------------
# 端到端闭环：solve
# ---------------------------------------------------------------------------

async def test_solve_closed_loop_end_to_end(tmp_path):
    store = MemoryStore(tmp_path)
    session = DigPoolSession(
        target=FIXTURE,
        planner=DeterministicPlanner(),
        validator=StubValidator(),
        memory=store,
        agent=DeterministicAgent(),
    )
    out = await session.solve("对技能包做一次安全测试")

    # plan → execute
    assert [s["phase"] for s in out["plan"]["subtasks"]] == list(PHASES)
    assert out["executions"] and out["executions"][0]["action"] == "tool"
    # verify：真实 skill-scan 命中 → 至少 1 条 confirmed
    assert out["counts"]["total"] >= 1
    assert out["counts"]["confirmed"] >= 1
    assert out["confirmed_findings"]
    # report + memory
    assert out["report_path"] and Path(out["report_path"]).exists()
    assert out["report_markdown"].startswith("# 鉴微 DigPool 安全测试报告")
    assert store.recall(out["memory_key"])["run_count"] == 1

    # 事件链完整
    phases = {e.phase for e in session.events}
    assert {SessionPhase.PLAN_CREATED, SessionPhase.VERIFIED,
            SessionPhase.REPORT_READY, SessionPhase.MEMORY_SAVED} <= phases


async def test_solve_second_run_can_recall_memory(tmp_path):
    store = MemoryStore(tmp_path)
    first = DigPoolSession(target=FIXTURE, planner=DeterministicPlanner(),
                           validator=StubValidator(), memory=store)
    await first.solve("第一次跑")
    second = DigPoolSession(target=FIXTURE, planner=DeterministicPlanner(),
                            validator=StubValidator(), memory=store)
    out = await second.solve("第二次跑")
    assert out["memory_recall"]["run_count"] == 1
    assert store.recall(out["memory_key"])["run_count"] == 2


# ---------------------------------------------------------------------------
# 零依赖：闭环组件在屏蔽第三方依赖时仍可导入与运行
# ---------------------------------------------------------------------------

def test_closure_agents_import_zero_dep():
    code = (
        "import sys, builtins\n"
        "_real = builtins.__import__\n"
        "BLOCK = {'yaml','httpx','openai','anthropic','fastapi','uvicorn','starlette','sse_starlette'}\n"
        "def _fake(name, *a, **k):\n"
        "    if name.split('.')[0] in BLOCK:\n"
        "        raise ImportError('blocked: ' + name)\n"
        "    return _real(name, *a, **k)\n"
        "builtins.__import__ = _fake\n"
        "import core.digpool\n"
        "from core.digpool import DeterministicPlanner, StubValidator, Reporter, MemoryStore\n"
        "from core.digpool.loops.loop_controller import Finding\n"
        "plan = DeterministicPlanner().plan('测 sqli', target='https://a.example.com')\n"
        "f = Finding(id='F1', vuln_type='XSS', severity='high', url='a/x', detail={'payload': 'p'})\n"
        "res = StubValidator().validate([f])\n"
        "md = Reporter().build(goal='g', target='https://a.example.com', plan=plan, validation=res)\n"
        "print('OK', len(plan.subtasks), res[0].verdict, md.startswith('# 鉴微'))\n"
    )
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=str(ROOT))
    assert r.returncode == 0, f"零依赖闭环导入失败:\n{r.stderr}"
    assert r.stdout.startswith("OK"), r.stdout

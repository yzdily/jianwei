"""DigPool 工作台 CLI 演示入口（零依赖，无需玄鉴引擎 / LLM 密钥）。

对齐 0912_XuanJian_AI_Demo_TechPlan.md：用最小可跑闭环验证「Agentic Loop + 多智能体 +
Memory + 工具链 + 治理门控」在鉴微底座上的可落地性。

用法：
    python -m core.digpool demo --target tests/fixtures/malicious_skill
    python -m core.digpool demo --target tests/fixtures/clean_skill
    python -m core.digpool tools            # 列出已注册 curated 工具
    python -m core.digpool loop --trigger sqli_possible   # 跑一次 LOOP 骨架
    python -m core.digpool plan --target https://api.example.com   # M1：目标 → 任务 DAG
    python -m core.digpool solve --target tests/fixtures/malicious_skill  # M1/M3/M4 闭环

设计纪律：复用 core/ 既有能力，不破玄鉴引擎边界；xuanjian 未安装时自动降级 StubCore。
"""
from __future__ import annotations

import argparse
import asyncio
import sys

from core.digpool import CORE_LINKED
from core.digpool.session import DigPoolSession
from core.digpool.tools.registry import list_tools
from core.digpool.tools.protocol import RiskLevel


def _print_header(title: str) -> None:
    print("\n" + "=" * 64)
    print(title)
    print("=" * 64)


async def _demo(target: str) -> int:
    _print_header("DigPool 工作台 Demo（Agentic Loop + Tool & Data + 治理）")
    print(f"后端：{'玄鉴引擎' if CORE_LINKED else 'StubCore（xuanjian 未安装，本地兜底）'}")
    print(f"目标：{target}\n")

    session = DigPoolSession(target=target)
    await session.open()

    # 1) Tool & Data 层：经治理门控调度真实检测器 skill-scan（低风险，自动放行）
    _print_header("① 工具链 · skill-scan（低风险，自动放行）")
    res = await session.run_tool("skill-scan", {"source": target, "strategy": "standard"})
    print(f"  裁决：risk={res.get('risk_level')} 治理拦截={res.get('blocked_by_governance', False)}")
    print(f"  结果：{res.get('summary')}")
    for f in res.get("findings", [])[:5]:
        print(f"    - [{f.severity}] {f.vuln_type} @ {f.url}")

    # 2) 治理门控：高风险工具 llm-top10 进入人工审批（演示审批单）
    _print_header("② 六维治理 · 高风险审批门（llm-top10 需人工）")
    res2 = await session.run_tool("llm-top10", {"url": "https://example.com/v1/chat"})
    print(f"  裁决：{res2.get('summary')}")
    if res2.get("approval_ticket_id"):
        print(f"  已生成审批单：{res2['approval_ticket_id']}（status=pending，需人工 approve）")

    # 3) Agentic Loop 骨架：跑一次 LOOP（DeterministicAgent 零依赖产出合成发现）
    _print_header("③ Agentic Loop 骨架 · LOOP 引擎（sqli_possible）")
    out = await session.run("sqli_possible")
    print(f"  backend={out['backend']} loop_controller={out['loop_controller']}")
    print(f"  depth_chain({out['depth_chain_len']}): {out['depth_chain']}")
    print(f"  termination={out['termination']} findings={out['findings']}")

    _print_header("Demo 完成 · 下一步见 MVP_GAP_ANALYSIS.md")
    # 退出码：skill-scan 命中高危则非 0（CI 门禁语义）
    return int(res.get("meta", {}).get("exit_code", 0))


def _list_tools() -> int:
    _print_header("已注册 curated 工具（Tool & Data 层）")
    for t in list_tools():
        print(f"  - {t.name}  [{t.risk_level.value}]  ({t.source})")
        print(f"      {t.description}")
    return 0


async def _loop(trigger: str) -> int:
    _print_header(f"LOOP 引擎 · trigger={trigger}")
    session = DigPoolSession(target="demo.local")
    out = await session.run(trigger)
    print(f"  depth_chain({out['depth_chain_len']}): {out['depth_chain']}")
    print(f"  termination={out['termination']} findings={out['findings']}")
    return 0


async def _plan(goal: str, target: str | None) -> int:
    _print_header("M1 Planner · 目标 → 任务 DAG")
    session = DigPoolSession(target=target)
    plan = await session.plan(goal)
    print(f"  目标：{plan.goal}")
    print(f"  解析目标：{plan.target}")
    print(f"  预算估算：{plan.budget_tokens} tokens")
    print("  子任务 DAG：")
    for st in plan.subtasks:
        extra = st.tool or st.trigger or ""
        dep = ",".join(st.depends_on) or "-"
        print(f"    - {st.id} [{st.phase}] ({st.action}{(':' + extra) if extra else ''}) dep={dep}")
        print(f"        {st.description}")
    return 0


async def _solve(goal: str, target: str | None, report_dir: str | None) -> int:
    _print_header("闭环 solve · plan → execute → verify → report → memory")
    from core.digpool.memory.store import MemoryStore

    memory = MemoryStore(report_dir) if report_dir else None
    session = DigPoolSession(target=target, memory=memory)
    out = await session.solve(goal)
    print(f"  目标：{out['goal']}")
    print(f"  计划阶段：{' → '.join(out['plan']['phases'])}（预算 {out['plan']['budget_tokens']} tokens）")
    for e in out["executions"]:
        if e.get("action") == "loop":
            print(f"  EXECUTE {e['subtask']}：{e['trigger']} depth={e['depth_chain']} termination={e['termination']}")
        else:
            print(f"  EXECUTE {e['subtask']}：{e['tool']} {e.get('summary')}")
    c = out["counts"]
    print(f"  验证：总发现 {c['total']}｜confirmed {c['confirmed']}｜suspect {c['suspect']}｜rejected {c['rejected']}")
    for fid in out["confirmed_findings"]:
        print(f"    ✅ {fid}")
    print(f"  报告：{out['report_path'] or '(未落盘)'}")
    print(f"  记忆：key={out['memory_key']}（历史运行 {out['memory_recall'].get('run_count', 0)} 次）")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="core.digpool", description="鉴微 DigPool 工作台（MVP Demo）")
    sub = parser.add_subparsers(dest="cmd")

    p_demo = sub.add_parser("demo", help="端到端演示：skill-scan + 治理 + LOOP")
    p_demo.add_argument("--target", default="tests/fixtures/malicious_skill", help="待扫目标（技能包目录）")

    sub.add_parser("tools", help="列出已注册 curated 工具")

    p_loop = sub.add_parser("loop", help="跑一次 LOOP 引擎骨架")
    p_loop.add_argument("--trigger", default="sqli_possible", help="LOOP trigger 名")

    p_plan = sub.add_parser("plan", help="M1：目标 → 任务 DAG + 预算")
    p_plan.add_argument("--goal", default="对目标做一次安全测试", help="自然语言目标")
    p_plan.add_argument("--target", default=None, help="被测目标（URL / 域名 / 本地技能包）")

    p_solve = sub.add_parser("solve", help="闭环：plan → execute → verify → report → memory")
    p_solve.add_argument("--goal", default="对目标做一次安全测试", help="自然语言目标")
    p_solve.add_argument("--target", default="tests/fixtures/malicious_skill", help="被测目标（URL / 域名 / 本地技能包）")
    p_solve.add_argument("--report-dir", default=None, help="记忆与报告落盘根目录（默认 <repo>/.digpool）")

    args = parser.parse_args(argv)
    cmd = args.cmd or "demo"

    try:
        if cmd == "demo":
            return asyncio.run(_demo(args.target))
        if cmd == "tools":
            return _list_tools()
        if cmd == "loop":
            return asyncio.run(_loop(args.trigger))
        if cmd == "plan":
            return asyncio.run(_plan(args.goal, args.target))
        if cmd == "solve":
            return asyncio.run(_solve(args.goal, args.target, args.report_dir))
    except KeyboardInterrupt:  # pragma: no cover
        return 130
    print("未知命令", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

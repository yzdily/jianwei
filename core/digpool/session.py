"""DigPoolSession —— 鉴微 DigPool 工作台会话（对标斗象蛙池AI 的 Agentic Loop 主循环骨架）。

M0 范围：
- 建立会话 + 事件流（SSE 可直接消费）
- 通过 core_link 复用玄鉴引擎，**空跑通**（不发射攻击），验证「复用 core 不破引擎边界」

M2（动态 Scope + 流量语料，关 0903 F11）：
- `ingest_traffic(corpus)` 运行时扩界；扩界受 `authorized` 授权白名单约束（F17 思想）

M3（F4 LOOP termination 真正钩入，关 0903 F4 遗留）：
- `run(trigger)` 实际调用 `LoopController.execute(trigger, context)`（玄鉴公开 API，不破边界）
- 产出 `depth_chain` 且 `termination` 原因非空（max_depth=3 + VulnChainMemory 去重防递归）

验收判据见 docs/digpool_workbench_roadmap.md 与
F:/xuanjian-main/hollowing-optimization-plan/plan/0912_digpool_milestones.md。
"""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Callable, Optional

from core.digpool.agent import BaseAgent, get_agent
from core.digpool.agents.planner import BasePlanner, Plan, get_planner
from core.digpool.agents.reporter import Reporter
from core.digpool.agents.validator import BaseValidator, get_validator
from core.digpool.core_link import CORE_LINKED, CoreBackend, get_core_backend, get_loop_controller
from core.digpool.memory.store import MemoryStore
from core.digpool.scope import Scope, ScopeUpdate, TrafficCorpus
from core.digpool.governance import Governance
from core.digpool.executor import ToolExecutor
from core.digpool.tools.protocol import RiskLevel, ToolCall
from core.log import get_logger

log = get_logger("core.digpool.session")


class SessionPhase:
    OPENED = "session_opened"
    CORE_LINKED = "core_linked"
    SCOPE_UPDATED = "scope_updated"
    RUN_STARTED = "run_started"
    RUN_FINISHED = "run_finished"
    PLAN_CREATED = "plan_created"
    VERIFIED = "verified"
    REPORT_READY = "report_ready"
    MEMORY_SAVED = "memory_saved"
    MESSAGE = "message"
    ERROR = "error"


@dataclass
class DigPoolEvent:
    phase: str
    type: str
    data: dict
    ts: float = field(default_factory=time.time)

    def to_sse(self) -> str:
        """序列化为 SSE 行（event: / data:）。"""
        payload = {"phase": self.phase, "type": self.type, "ts": self.ts, "data": self.data}
        return f"event: {self.phase}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"


class DigPoolSession:
    def __init__(
        self,
        session_id: Optional[str] = None,
        target: Optional[str] = None,
        scope: Any = None,
        backend: Optional[CoreBackend] = None,
        loop_controller: Any = None,
        agent: Optional[BaseAgent] = None,
        governance: Optional[Governance] = None,
        planner: Optional[BasePlanner] = None,
        validator: Optional[BaseValidator] = None,
        reporter: Optional[Reporter] = None,
        memory: Optional[MemoryStore] = None,
    ):
        self.session_id = session_id or uuid.uuid4().hex
        self.target = target
        # M2：scope 统一为 Scope 对象（兼容 dict 入参，M0 接口不破坏）
        if isinstance(scope, Scope):
            self.scope = scope
        elif isinstance(scope, dict):
            self.scope = Scope.from_dict(scope)
        else:
            self.scope = Scope()
        self.backend: CoreBackend = backend or get_core_backend()
        # 六维治理（M3/M4）：审批门 + 熔断，低风险自动 / 高风险人工
        self.governance = governance or Governance()
        self.executor = ToolExecutor(self.governance)
        # M3：loop controller 可注入（便于测试 spy），默认经 core_link 取可用实现
        self._loop_controller = loop_controller or get_loop_controller()()
        # M4：Agent 可注入（便于测试）；默认按环境选择（LLM key 在则用真实 LLM，否则确定性兜底）
        self.agent: BaseAgent = agent or get_agent()
        # M1/M3/M4 闭环组件：Planner / Validator / Reporter / Memory（均可注入，便于测试与降级）
        self.planner: BasePlanner = planner or get_planner()
        self.validator: BaseValidator = validator or get_validator()
        self.reporter: Reporter = reporter or Reporter()
        self.memory: MemoryStore = memory or MemoryStore()
        self.last_findings: list[Any] = []  # run() 最近一次产出的 Finding 对象（供 solve 闭环消费）
        self.events: list[DigPoolEvent] = []
        self._handle: Any = None

    # ---- 内部 ----
    def _emit(self, phase: str, etype: str, data: dict) -> DigPoolEvent:
        ev = DigPoolEvent(phase=phase, type=etype, data=data)
        self.events.append(ev)
        return ev

    async def open(self) -> "DigPoolSession":
        self._handle = await self.backend.open_session(self.session_id, self.target, self.scope.to_dict())
        self._emit(SessionPhase.OPENED, "session", {
            "session_id": self.session_id,
            "target": self.target,
            "scope": self.scope.to_dict(),
        })
        self._emit(SessionPhase.CORE_LINKED, "core", {
            "backend": self.backend.backend_name,
            "linked": CORE_LINKED,
        })
        return self

    # ---------- M0：空跑通（不破引擎边界） ----------
    async def run_empty(self) -> dict:
        """M0 空跑通：复用 core 但不发射任何真实攻击，仅验证调用边界完整。"""
        if self._handle is None:
            await self.open()
        self._emit(SessionPhase.RUN_STARTED, "run", {"mode": "empty"})
        result = await self.backend.passthrough(self._handle)
        result["boundary_intact"] = True
        result["core_linked"] = CORE_LINKED
        result["backend"] = self.backend.backend_name
        self._emit(SessionPhase.RUN_FINISHED, "run", result)
        return result

    # ---------- M2：动态 Scope + 流量语料 ----------
    async def ingest_traffic(self, corpus: TrafficCorpus) -> ScopeUpdate:
        """摄入流量语料，运行时扩界（受 authorized 白名单约束，F17 思想）。

        Args:
            corpus: 代理/合规证书抓包 → 语义语料。

        Returns:
            ScopeUpdate：本次新增与拒绝的域名/端点集合。

        Emits:
            scope_updated 事件（含 before/after 快照），供 SSE 消费与 M2 测试断言。
        """
        domains, endpoints = corpus.candidates()
        before = self.scope.to_dict()
        update = self.scope.expand(domains=domains, endpoints=endpoints)
        after = self.scope.to_dict()
        self._emit(SessionPhase.SCOPE_UPDATED, "scope", {
            "source": corpus.source,
            "before": before,
            "after": after,
            "update": update.to_dict(),
        })
        return update

    # ---------- M2b：代理/合规证书抓包 → 流量语料 → 运行时扩界 ----------
    async def ingest_proxy_capture(self, dump_path: str, *, inline_records: list[dict] | None = None) -> ScopeUpdate:
        """从代理抓包（mitmproxy 流导出 / 访问日志）摄入语料并扩界。

        Args:
            dump_path: 服务端代理流导出文件路径（JSON Lines 或通用访问日志）。
            inline_records: 可选内联记录（不读文件，便于 API 直接传参）。

        Returns:
            ScopeUpdate：本次扩界结果。
        """
        from core.digpool.ingest import ProxyTrafficSource

        if inline_records is not None:
            corpus = TrafficCorpus.from_records("proxy", inline_records)
        else:
            corpus = ProxyTrafficSource.from_mitmproxy_dump(dump_path)
        return await self.ingest_traffic(corpus)

    async def ingest_compliance_certs(self, path_or_text: str, *, is_text: bool = False) -> ScopeUpdate:
        """从合规证书抓包（openssl 证书文本 / JSON）提取 SAN/CN 域名并扩界。

        Args:
            path_or_text: 证书元数据文件路径；is_text=True 时直接作为证书文本解析。
            is_text: True 表示 path_or_text 是证书文本而非路径。

        Returns:
            ScopeUpdate：本次扩界结果。
        """
        from core.digpool.ingest import ComplianceCertSource

        if is_text:
            corpus = ComplianceCertSource.from_cert_text(path_or_text)
        else:
            corpus = ComplianceCertSource.from_cert_dump(path_or_text)
        return await self.ingest_traffic(corpus)
    async def run(
        self,
        trigger: str,
        *,
        step_handler: Optional[Callable[[dict, dict], Any]] = None,
    ) -> dict:
        """真正钩入玄鉴 LOOP 引擎：实调 LoopController.execute(trigger, context)。

        M4：step_handler 缺省时自动绑定 self.agent（真实 Agent 调用），让每个 LOOP 步骤
        由 Agent 驱动产出 Finding；Agent 受 scope 授权边界约束（越权动作 refuse）。

        不破边界：仅经 LoopController 公开 step_handler 钩子调用，不修改玄鉴循环体。

        Args:
            trigger: loop_matrix 中的触发类型（如 "actuator_exposure"）。
            step_handler: 可选回调 (step_def, context) -> Finding|None；不提供则接真实 Agent。

        Returns:
            dict：含 depth_chain、termination 原因、findings、boundary_intact。
        """
        if self._handle is None:
            await self.open()
        self._emit(SessionPhase.RUN_STARTED, "run", {"mode": "loop", "trigger": trigger})

        ctl = self._loop_controller
        context: dict[str, Any] = {
            "target": self.target,
            "scope_domains": sorted(self.scope.domains),
            "scope_endpoints": sorted(self.scope.endpoints),
        }
        # M4：step_handler 缺省 → 绑定真实 Agent（满足 LoopController 的 (step, context) 签名）
        if step_handler is None:
            step_handler = self.agent.bind(self.scope)
        # ★ 关键钩入点：必须实际调用 LoopController.execute（M3 硬指标）
        findings = await ctl.execute(trigger, context, step_handler=step_handler)
        self.last_findings = list(findings)  # 供 solve 闭环取回 Finding 对象

        depth_chain = [s.step for s in ctl.chain.get_chain(trigger)]
        termination = self._resolve_termination(trigger, context)
        result = {
            "trigger": trigger,
            "backend": self.backend.backend_name,
            "loop_controller": type(ctl).__name__,
            "depth_chain_len": len(depth_chain),
            "depth_chain": depth_chain,
            "termination": termination,
            "findings": [getattr(f, "id", None) for f in findings],
            "boundary_intact": True,
            "core_linked": CORE_LINKED,
        }
        self._emit(SessionPhase.RUN_FINISHED, "run", result)
        return result

    def _resolve_termination(self, trigger: str, context: dict[str, Any]) -> str:
        """从 loop_matrix termination 字段 + depth_chain 长度推导非空终止原因。"""
        defn = self._loop_controller.get_trigger(trigger) or {}
        # 1) 命中显式终止条件
        for t in defn.get("termination", []):
            if context.get(t):
                return t
        depth = self._loop_controller.chain.get_depth(trigger)
        matrix_depth = len(defn.get("depth_chain", []))
        # 2) 链走满（max_depth 或矩阵定义链长）
        if matrix_depth and depth >= matrix_depth:
            return "max_depth_reached"
        # 3) 至少有 2 步（满足 M3 len(depth_chain) ≥ 2）
        if depth >= 2:
            return "depth_chain_completed"
        if depth == 1:
            return "single_step_completed"
        return "no_depth"

    # ---------- M1：目标 → 任务 DAG（Planner） ----------
    async def plan(self, goal: str) -> Plan:
        """把自然语言目标解析为子任务 DAG + 预算估算（M1 Planner）。

        若注入的是 LLMPlanner（有 aplan），驱动真实 LLM 规划；否则确定性 Planner。
        仅消费 Planner 公开接口，不破引擎边界。

        Emits:
            plan_created 事件（含 DAG / 邻接边 / 预算），供 SSE 与报告消费。
        """
        if self._handle is None:
            await self.open()
        if hasattr(self.planner, "aplan"):
            plan = await self.planner.aplan(goal, target=self.target, scope=self.scope.to_dict())
        else:
            plan = self.planner.plan(goal, target=self.target, scope=self.scope.to_dict())
        self._emit(SessionPhase.PLAN_CREATED, "plan", plan.to_dict())
        return plan

    # ---------- M1/M3/M4：闭环 solve（plan → execute → verify → report → memory） ----------
    async def solve(self, goal: str, *, auto_approve_high: bool = True, save: bool = True) -> dict:
        """执行一次完整闭环：规划 → 执行 → 验证 → 报告 → 记忆。

        分工：
        - Planner（M1）产出 DAG；EXECUTE 阶段按 subtask 派发（本地技能包 → skill-scan 工具；
          远程端点 → LOOP trigger，经 Agent 驱动并受 scope 约束）。
        - Validator（M3）双重去误报，仅 confirmed 进入报告已确认清单。
        - Reporter（M4）渲染可交付报告并落盘；MemoryStore（M4）沉淀项目记忆。

        Args:
            goal: 自然语言目标。
            auto_approve_high: 高风险工具是否自动放行（默认 True，便于端到端演示；生产应置 False）。
            save: 是否落盘报告与记忆。

        Returns:
            dict：plan / executions / validation / counts / report_markdown / report_path / memory_key。
        """
        if self._handle is None:
            await self.open()
        self._emit(SessionPhase.RUN_STARTED, "solve", {"goal": goal})
        plan = await self.plan(goal)

        # 预算计量（六维治理 · Budget）：超额即熔断（仍继续出报告，但如实标注）
        budget = self.governance.charge(plan.budget_tokens)

        executions: list[dict] = []
        findings: list[Any] = []
        triggers: list[str] = []
        for st in plan.subtasks:
            if st.phase != "EXECUTE":
                continue
            if st.action == "tool" and st.tool:
                res = await self.run_tool(st.tool, st.args, auto_approve_high=auto_approve_high)
                findings.extend(res.get("findings") or [])
                executions.append({
                    "subtask": st.id, "action": "tool", "tool": st.tool,
                    "ok": res.get("ok", False), "summary": res.get("summary", ""),
                    "blocked_by_governance": res.get("blocked_by_governance", False),
                })
            elif st.action == "loop" and st.trigger:
                out = await self.run(st.trigger)
                findings.extend(self.last_findings)
                triggers.append(st.trigger)
                executions.append({
                    "subtask": st.id, "action": "loop", "trigger": st.trigger,
                    "depth_chain": out.get("depth_chain_len", 0),
                    "termination": out.get("termination"),
                })

        # M3 · 双重去误报
        validation = self.validator.validate(findings, context={"target": self.target, "goal": goal})
        confirmed = [r for r in validation if r.verified]
        counts = {
            "total": len(findings),
            "confirmed": len(confirmed),
            "suspect": sum(1 for r in validation if r.verdict == "suspect"),
            "rejected": sum(1 for r in validation if r.verdict == "rejected"),
        }
        self._emit(SessionPhase.VERIFIED, "verify", counts)

        # M4 · 报告 + 项目记忆
        project_key = self.memory.project_key_for(self.target or goal)
        recall_before = self.memory.recall(project_key)
        run_id = f"RUN-{uuid.uuid4().hex[:8]}"
        report_md = self.reporter.build(
            goal=goal, target=self.target, session_id=self.session_id, run_id=run_id,
            plan=plan, executions=executions, validation=validation,
            memory_key=project_key, memory_recall=recall_before,
            extra={"预算熔断": "否" if budget.allow else "是"},
        )
        report_path: Optional[str] = None
        if save:
            saved = self.memory.save_report(project_key, run_id, report_md)
            report_path = str(saved)
            self.memory.save_run(project_key, {
                "run_id": run_id, "goal": goal, "target": self.target,
                "vuln_types": sorted({r.finding.vuln_type for r in confirmed if getattr(r.finding, "vuln_type", None)}),
                "triggers": triggers,
                "termination": executions[-1].get("termination") if executions else None,
                "confirmed": counts["confirmed"],
                "report_path": report_path,
            })
            self._emit(SessionPhase.MEMORY_SAVED, "memory", {"key": project_key, "run_id": run_id})
        self._emit(SessionPhase.REPORT_READY, "report", {"path": report_path})

        result = {
            "goal": goal,
            "target": self.target,
            "session_id": self.session_id,
            "run_id": run_id,
            "backend": self.backend.backend_name,
            "plan": plan.to_dict(),
            "executions": executions,
            "validation": [r.to_dict() for r in validation],
            "counts": counts,
            "confirmed_findings": [getattr(r.finding, "id", None) for r in confirmed],
            "report_markdown": report_md,
            "report_path": report_path,
            "memory_key": project_key,
            "memory_recall": recall_before,
            "boundary_intact": True,
        }
        self._emit(SessionPhase.RUN_FINISHED, "solve", result)
        return result

    # ---------- 对话入口（M0 占位，M2/M3 钩子已预留） ----------
    async def chat(self, message: str) -> dict:
        """M0 对话入口（占位）：回显 + 触发一次空跑验证。M2 起接真实 LLM/Agent。"""
        await self.open()
        self._emit(SessionPhase.MESSAGE, "user", {"content": message})
        res = await self.run_empty()
        reply = (
            f"[M0 echo] {message} ｜ backend={self.backend.backend_name} "
            f"boundary_intact={res.get('boundary_intact')} "
            f"scope_domains={sorted(self.scope.domains)}"
        )
        self._emit(SessionPhase.MESSAGE, "assistant", {"content": reply})
        return {
            "reply": reply,
            "session_id": self.session_id,
            "core_linked": CORE_LINKED,
            "boundary_intact": True,
            "backend": self.backend.backend_name,
            "scope": self.scope.to_dict(),
        }

    async def achat(self, message: str) -> AsyncIterator[DigPoolEvent]:
        """流式对话（M0）：逐步 yield 事件，供 SSE 端点直接消费。"""

        def _yield_new(since: int):
            for ev in self.events[since:]:
                yield ev

        n0 = len(self.events)
        await self.open()
        for ev in _yield_new(n0):
            yield ev

        n1 = len(self.events)
        self._emit(SessionPhase.MESSAGE, "user", {"content": message})
        for ev in _yield_new(n1):
            yield ev

        n2 = len(self.events)
        res = await self.run_empty()
        for ev in _yield_new(n2):
            yield ev

        n3 = len(self.events)
        reply = (
            f"[M0 echo] {message} ｜ backend={self.backend.backend_name} "
            f"boundary_intact={res.get('boundary_intact')}"
        )
        self._emit(SessionPhase.MESSAGE, "assistant", {"content": reply})
        for ev in _yield_new(n3):
            yield ev

    # ---------- Tool & Data 层：调度真实检测器（M2b/M4 桥接 jianwei 检测能力） ----------
    async def run_tool(self, tool_name: str, args: dict | None = None, *, auto_approve_high: bool = False) -> dict:
        """经治理门控调度一个 curated 工具（如 skill-scan / llm-top10）。

        对齐 TechPlan §4.3：Tool 经 governance 审批门（高风险人工）后由 Executor 派发，
        结果转 LOOP Finding 回流会话。

        Args:
            tool_name: 注册工具名（见 core.digpool.tools.builtins）。
            args: 工具参数。
            auto_approve_high: True 时高风险工具也自动放行（仅演示/授权场景）。

        Returns:
            dict：含治理裁决、工具结果、规范 Finding 列表。
        """
        self.governance.auto_approve_high = auto_approve_high
        from core.digpool.tools.registry import get_tool as _gt

        t = _gt(tool_name)
        risk = t.risk_level if t else RiskLevel.LOW
        call = ToolCall(tool=tool_name, args=args or {}, risk_level=risk)
        self._emit(SessionPhase.RUN_STARTED, "tool", {"tool": tool_name, "args": args or {}})
        result = await self.executor.run(call)
        result["risk_level"] = risk.value
        self._emit(SessionPhase.RUN_FINISHED, "tool", result)
        return result

    async def arun(self, trigger: str, *, step_handler: Optional[Callable[[dict, dict], Any]] = None) -> AsyncIterator[DigPoolEvent]:
        """流式 LOOP 运行（M3）：逐步 yield open + run 事件，供 SSE 端点消费。"""

        def _yield_new(since: int):
            for ev in self.events[since:]:
                yield ev

        n0 = len(self.events)
        await self.open()
        for ev in _yield_new(n0):
            yield ev

        n1 = len(self.events)
        await self.run(trigger, step_handler=step_handler)
        for ev in _yield_new(n1):
            yield ev


__all__ = ["DigPoolSession", "DigPoolEvent", "SessionPhase", "Scope", "TrafficCorpus", "ScopeUpdate"]

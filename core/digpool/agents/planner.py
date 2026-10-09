"""M1 · Planner —— 自然语言目标 → 任务 DAG + 预算估算。

对齐《鉴微优化方案 §5》M1：把用户目标解析为
`RECON → SCOPE → EXECUTE → VERIFY → REPORT` 的子任务 DAG，并给出预算估算。

设计纪律（同 core_link / agent）：
- **不依赖玄鉴内部类**：Planner 只产出计划，不直接触碰引擎；
- **零依赖可跑**：LLM 缺失时降级 `DeterministicPlanner`，任意环境都能出 DAG。
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Optional

from core.log import get_logger

log = get_logger("core.digpool.agents.planner")

# 阶段顺序（覆盖矩阵的列）
PHASES: tuple[str, ...] = ("RECON", "SCOPE", "EXECUTE", "VERIFY", "REPORT")

# 各阶段默认预算（估算 token；EXECUTE 最重）
_PHASE_BUDGET: dict[str, int] = {
    "RECON": 2_000,
    "SCOPE": 1_000,
    "EXECUTE": 12_000,
    "VERIFY": 3_000,
    "REPORT": 2_000,
}

# 目标关键词 → LOOP trigger（用于把自然语言意图落到具体深度链）
_TRIGGER_KEYWORDS: tuple[tuple[str, str], ...] = (
    ("sql注入", "sqli_possible"),
    ("sqli", "sqli_possible"),
    ("ssrf", "ssrf_possible"),
    ("xss", "xss_possible"),
    ("actuator", "actuator_exposure"),
    ("heapdump", "heapdump_leak"),
    ("shiro", "shiro_remmeberme_active"),
    ("环境变量", "actuator_env_leak"),
    ("env", "actuator_env_leak"),
    ("路径穿越", "path_normalization_bypass"),
    ("越权", "vertical_privilege_escalation"),
    ("权限提升", "vertical_privilege_escalation"),
    ("未授权", "unauthenticated_read"),
    ("参数", "param_config_leak"),
)
_DEFAULT_TRIGGER = "actuator_exposure"

_URL_RE = re.compile(r"https?://[^\s\"'<>）)]+", re.I)
_HOST_RE = re.compile(r"\b([a-z0-9-]+(?:\.[a-z0-9-]+)+)\b", re.I)
_PATH_RE = re.compile(r"[A-Za-z0-9_.\-]*[\\/][A-Za-z0-9_.\\/\-]+")


@dataclass
class SubTask:
    """计划中的一个子任务节点（DAG node）。"""

    id: str
    phase: str
    description: str
    action: str = "step"          # step | tool | loop
    depends_on: tuple[str, ...] = ()
    tool: Optional[str] = None
    args: dict = field(default_factory=dict)
    trigger: Optional[str] = None
    budget_tokens: int = 0

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "phase": self.phase,
            "description": self.description,
            "action": self.action,
            "depends_on": list(self.depends_on),
            "tool": self.tool,
            "args": self.args,
            "trigger": self.trigger,
            "budget_tokens": self.budget_tokens,
        }


@dataclass
class Plan:
    """一次任务计划：目标 + 子任务 DAG + 预算。"""

    goal: str
    target: Optional[str]
    subtasks: list[SubTask]
    budget_tokens: int

    def phases(self) -> list[str]:
        return [s.phase for s in self.subtasks]

    def edges(self) -> list[tuple[str, str]]:
        return [(dep, s.id) for s in self.subtasks for dep in s.depends_on]

    def to_dict(self) -> dict:
        return {
            "goal": self.goal,
            "target": self.target,
            "budget_tokens": self.budget_tokens,
            "phases": self.phases(),
            "subtasks": [s.to_dict() for s in self.subtasks],
            "edges": self.edges(),
        }


# ---------------------------------------------------------------------------
# 解析辅助
# ---------------------------------------------------------------------------

def _extract_target(goal: str) -> Optional[str]:
    """从自然语言目标里尽力抽取被测目标（URL > 裸域名 > 本地路径）。"""
    if not goal:
        return None
    m = _URL_RE.search(goal)
    if m:
        return m.group(0).rstrip(".,，。；;")
    m = _HOST_RE.search(goal)
    if m:
        return m.group(1)
    m = _PATH_RE.search(goal)
    if m:
        return m.group(0)
    return None


def _looks_local(target: Optional[str]) -> bool:
    """本地技能包/文件（本地路径）vs 远程端点（URL/域名）。"""
    if not target:
        return False
    if re.match(r"^https?://", target, re.I):
        return False
    if _HOST_RE.fullmatch(target):
        return False
    return ("/" in target) or ("\\" in target) or os.path.exists(target)


def _infer_trigger(goal: str, target: Optional[str]) -> str:
    haystack = f"{goal or ''} {target or ''}".lower()
    for key, trigger in _TRIGGER_KEYWORDS:
        if key in haystack:
            return trigger
    return _DEFAULT_TRIGGER


# ---------------------------------------------------------------------------
# Planner 实现
# ---------------------------------------------------------------------------

class BasePlanner:
    """Planner 基类。"""

    name = "base"

    def plan(self, goal: str, *, target: Optional[str] = None, scope: Optional[dict] = None) -> Plan:
        raise NotImplementedError


class DeterministicPlanner(BasePlanner):
    """离线/测试 Planner：按规则确定性生成 DAG，零 LLM 依赖。"""

    name = "deterministic"

    def plan(self, goal: str, *, target: Optional[str] = None, scope: Optional[dict] = None) -> Plan:
        target = target or _extract_target(goal)
        local = _looks_local(target)
        trigger = _infer_trigger(goal, target)

        if local:
            exec_desc = f"对本地技能包 `{target}` 做静态供应链扫描（只读不执行）"
            exec_action, tool, trig = "tool", "skill-scan", None
            exec_args: dict = {"source": target, "strategy": "standard"}
        else:
            exec_desc = f"按 LOOP 深度链执行触发 `{trigger}`（Agent 驱动，受 scope 约束）"
            exec_action, tool, trig = "loop", None, trigger
            exec_args = {}

        subtasks = [
            SubTask(
                id="t1", phase="RECON",
                description=f"识别资产与攻击面：{target or '(未指定目标)'}",
                action="tool", tool="asset-discovery",
                args={"target": target} if target else {},
                budget_tokens=_PHASE_BUDGET["RECON"],
            ),
            SubTask(
                id="t2", phase="SCOPE",
                description="据流量语料在授权白名单内修正测试边界",
                action="step", depends_on=("t1",),
                budget_tokens=_PHASE_BUDGET["SCOPE"],
            ),
            SubTask(
                id="t3", phase="EXECUTE", description=exec_desc,
                action=exec_action, tool=tool, trigger=trig, args=exec_args,
                depends_on=("t2",), budget_tokens=_PHASE_BUDGET["EXECUTE"],
            ),
            SubTask(
                id="t4", phase="VERIFY",
                description="双重去误报（证据门 + 佐证门），仅确定性漏洞进入报告",
                action="step", depends_on=("t3",),
                budget_tokens=_PHASE_BUDGET["VERIFY"],
            ),
            SubTask(
                id="t5", phase="REPORT",
                description="生成可交付报告 + 项目记忆落盘",
                action="step", depends_on=("t4",),
                budget_tokens=_PHASE_BUDGET["REPORT"],
            ),
        ]
        budget = sum(s.budget_tokens for s in subtasks)
        return Plan(goal=goal, target=target, subtasks=subtasks, budget_tokens=budget)


class LLMPlanner(BasePlanner):
    """真实 LLM Planner：OpenAI 兼容端点产出 JSON 计划；失败即降级确定性 Planner。

    环境变量同 LLMAgent：DIGPOOL_LLM_BASE_URL / DIGPOOL_LLM_API_KEY / DIGPOOL_LLM_MODEL。
    """

    name = "llm"

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        client: Any = None,
        fallback: Optional[BasePlanner] = None,
    ):
        self.base_url = (base_url or os.getenv("DIGPOOL_LLM_BASE_URL") or "https://api.openai.com/v1").rstrip("/")
        self.api_key = api_key or os.getenv("DIGPOOL_LLM_API_KEY") or ""
        self.model = model or os.getenv("DIGPOOL_LLM_MODEL") or "gpt-4o-mini"
        self._client = client
        self._fallback = fallback or DeterministicPlanner()

    def _messages(self, goal: str, target: Optional[str], scope: Optional[dict]) -> list[dict]:
        system = (
            "你是鉴微 DigPool 的规划器。把用户目标拆解为子任务 DAG，阶段固定为 "
            "RECON→SCOPE→EXECUTE→VERIFY→REPORT。\n"
            "EXECUTE 阶段：本地技能包用 tool=skill-scan；远程端点用 loop trigger（如 actuator_exposure/"
            "sqli_possible/ssrf_possible/xss_possible）。\n"
            "只返回严格 JSON：{\"target\": \"<url或路径>\", "
            "\"subtasks\": [{\"phase\": \"...\", \"description\": \"...\", "
            "\"action\": \"step|tool|loop\", \"tool\": \"...\", \"trigger\": \"...\"}]}。"
        )
        user = (
            f"目标：{goal}\n已知目标：{target or '(无)'}\n"
            f"scope：{json.dumps(scope or {}, ensure_ascii=False)}"
        )
        return [{"role": "system", "content": system}, {"role": "user", "content": user}]

    async def _call_llm(self, messages: list[dict]) -> str:
        payload = {
            "model": self.model, "messages": messages,
            "temperature": 0.2, "response_format": {"type": "json_object"},
        }
        if self._client is not None:
            resp = await self._client.post(f"{self.base_url}/chat/completions", json=payload)
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]
        import httpx  # 懒加载，离线不强制依赖

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{self.base_url}/chat/completions", json=payload,
                headers={"Authorization": f"Bearer {self.api_key}"},
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]

    async def aplan(self, goal: str, *, target: Optional[str] = None, scope: Optional[dict] = None) -> Plan:
        try:
            raw = await self._call_llm(self._messages(goal, target, scope))
            data = _parse_json(raw)
            plan = self._to_plan(goal, target, data)
            if plan.subtasks:
                return plan
        except Exception as exc:  # noqa: BLE001 - 任意失败都降级，保证闭环不中断
            log.warning(f"LLMPlanner 失败，降级 DeterministicPlanner: {exc}")
        return self._fallback.plan(goal, target=target, scope=scope)

    def plan(self, goal: str, *, target: Optional[str] = None, scope: Optional[dict] = None) -> Plan:
        # 同步入口：不驱动 LLM（避免事件循环耦合），直接给确定性计划；
        # 需要 LLM 计划请 await aplan()。
        return self._fallback.plan(goal, target=target, scope=scope)

    def _to_plan(self, goal: str, target: Optional[str], data: dict) -> Plan:
        resolved_target = data.get("target") or target or _extract_target(goal)
        rows = data.get("subtasks") or []
        subtasks: list[SubTask] = []
        budget = 0
        for i, row in enumerate(rows, start=1):
            phase = str(row.get("phase") or "").upper()
            if phase not in PHASES:
                continue
            b = _PHASE_BUDGET.get(phase, 1_000)
            budget += b
            subtasks.append(SubTask(
                id=f"t{i}", phase=phase,
                description=str(row.get("description") or phase),
                action=str(row.get("action") or "step"),
                depends_on=(f"t{i - 1}",) if i > 1 else (),
                tool=row.get("tool"), trigger=row.get("trigger"),
                budget_tokens=b,
            ))
        return Plan(goal=goal, target=resolved_target, subtasks=subtasks, budget_tokens=budget)


def _parse_json(text: str) -> dict:
    """尽力从 LLM 输出中解析 JSON（容错 markdown 围栏/多余文本）。"""
    text = (text or "").strip()
    if not text:
        return {}
    try:
        return json.loads(text)
    except Exception:
        pass
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    if fenced:
        try:
            return json.loads(fenced.group(1))
        except Exception:
            pass
    m = re.search(r"\{.*\}", text, re.S)
    if m:
        try:
            return json.loads(m.group(0))
        except Exception:
            pass
    return {}


def get_planner() -> BasePlanner:
    """按环境选择 Planner：配置 DIGPOOL_LLM_API_KEY 用 LLMPlanner，否则确定性兜底。"""
    if os.getenv("DIGPOOL_LLM_API_KEY"):
        return LLMPlanner()
    return DeterministicPlanner()


__all__ = [
    "PHASES", "SubTask", "Plan",
    "BasePlanner", "DeterministicPlanner", "LLMPlanner", "get_planner",
]

"""DigPool 真实 Agent 调用（M4 / Agentic Loop 驱动）。

把 run(trigger, step_handler=...) 的 step_handler 接到真实 Agent：
- LLMAgent：调用 OpenAI 兼容 Chat Completions 端点（httpx async），按 LOOP 步骤做安全推理，
  返回结构化 Finding；受 ScopeGuard 约束，越权目标直接拒绝（不破引擎边界）。
- DeterministicAgent：离线/测试备用，按规则确定性产出 Finding，保证无 LLM 环境也能闭环。

设计纪律（同 core_link）：
- 不依赖玄鉴内部类；仅消费 DigPoolSession 的 Scope，边界纪律不变。
- Agent 只能在 scope 授权/已知域内动作；越权目标 refuse，绝不自动扩界（扩界必须走 M2 ingest）。
"""
from __future__ import annotations

import json
import os
import re
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Optional

from core.digpool.loops.loop_controller import Finding
from core.digpool.scope import Scope, _extract_host
from core.log import get_logger

log = get_logger("core.digpool.agent")

ENV_BASE_URL = "DIGPOOL_LLM_BASE_URL"
ENV_API_KEY = "DIGPOOL_LLM_API_KEY"
ENV_MODEL = "DIGPOOL_LLM_MODEL"


@dataclass
class AgentDecision:
    """Agent 对单个 LOOP 步骤的决策。"""

    action: str  # simulate | refuse | observe
    target: Optional[str]
    finding: Optional[Finding]
    done: bool = False
    rationale: str = ""
    out_of_scope: bool = False


class ScopeGuard:
    """Agent 动作边界守卫：仅允许落在 scope 授权/已知域内的目标。"""

    def __init__(self, scope: Scope):
        self.scope = scope

    def allows(self, target: Optional[str]) -> bool:
        if not target:
            # 无具体目标（如"分析上下文"）视为允许
            return True
        host = _extract_host(target)
        if not host:
            return True
        return self.scope._is_authorized(host)


class BaseAgent:
    """Agent 基类：bind(scope) 生成满足 LoopController step_handler 签名的闭包。"""

    def bind(self, scope: Scope) -> Callable[[dict, dict], Any]:
        """返回 (step, context) -> Finding|None，供 LoopController.execute 逐深度调用。"""

        guard = ScopeGuard(scope)

        async def handler(step: dict, context: dict) -> Any:
            decision = await self.decide(step, context, guard)
            if decision.out_of_scope or (decision.target and not guard.allows(decision.target)):
                log.warning(f"Agent 越权动作被拒: target={decision.target} (不在授权 scope)")
                return None
            return decision.finding

        return handler

    async def decide(self, step: dict, context: dict, guard: ScopeGuard) -> AgentDecision:
        raise NotImplementedError


_VULN_MAP = [
    ("recon", "Information_Disclosure"),
    ("exposure", "Actuator_Exposure"),
    ("env", "Env_Secret_Leak"),
    ("cred", "Credential_Leak"),
    ("heapdump", "Heapdump_Leak"),
    ("exploit", "RCE"),
    ("verify", "Confirmation"),
    ("rce", "RCE"),
    ("deserial", "Insecure_Deserialization"),
    ("sqli", "SQL_Injection"),
    ("ssrf", "SSRF"),
    ("xss", "XSS"),
]


def _vuln_for(step_name: str) -> str:
    s = (step_name or "").lower()
    for key, vuln in _VULN_MAP:
        if key in s:
            return vuln
    return "Generic"


class DeterministicAgent(BaseAgent):
    """离线/测试 Agent：按 step 名称与 context 确定性构造 Finding。

    无 LLM 依赖，保证任意环境（含未配置 DIGPOOL_LLM_API_KEY 的开发机）都能跑通 Agentic Loop。
    """

    async def decide(self, step: dict, context: dict, guard: ScopeGuard) -> AgentDecision:
        step_name = step.get("step", "unknown")
        target = context.get("target")
        # 守卫前置：target 越权则直接 refuse（双层保险，bind 处还会再判一次）
        if target and not guard.allows(target):
            return AgentDecision(
                action="refuse", target=target, finding=None,
                out_of_scope=True, rationale="target 不在授权 scope 内",
            )
        fid = f"FIND-{uuid.uuid4().hex[:8]}"
        finding = Finding(
            id=fid,
            vuln_type=_vuln_for(step_name),
            severity="Medium",
            url=target or "",
            detail={
                "step": step_name,
                "agent": "deterministic",
                "scope_domains": sorted(context.get("scope_domains", [])),
            },
            extracted_artifacts={"observed_step": step_name, "agent": "deterministic"},
        )
        return AgentDecision(
            action="simulate", target=target, finding=finding, done=False,
            rationale=f"确定性模拟 step={step_name}",
        )


class LLMAgent(BaseAgent):
    """真实 LLM Agent：OpenAI 兼容端点，按 step 做安全推理返回结构化 Finding。

    默认端点 https://api.openai.com/v1，可用环境变量覆盖：
      DIGPOOL_LLM_BASE_URL / DIGPOOL_LLM_API_KEY / DIGPOOL_LLM_MODEL
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        client: Any = None,
    ):
        self.base_url = (base_url or os.getenv(ENV_BASE_URL) or "https://api.openai.com/v1").rstrip("/")
        self.api_key = api_key or os.getenv(ENV_API_KEY) or ""
        self.model = model or os.getenv(ENV_MODEL) or "gpt-4o-mini"
        # 可注入（测试用 mock httpx.AsyncClient）；为 None 时运行时新建真实 client
        self._client = client

    def _messages(self, step: dict, context: dict, guard: ScopeGuard) -> list[dict]:
        scope_domains = sorted(context.get("scope_domains", []))
        authorized = sorted(guard.scope.authorized) if guard.scope.authorized else ["(未限定，仅已知域)"]
        system = (
            "你是鉴微 DigPool 的安全推理 Agent，运行在授权渗透测试范围内。\n"
            "给定 LOOP 引擎的一个步骤定义与上下文，请决定本次动作：\n"
            "1) 仅可在以下授权 scope 内操作（域名白名单）；越权目标必须 refuse。\n"
            f"已知 scope 域名：{', '.join(scope_domains) or '(空)'}\n"
            f"授权白名单：{', '.join(authorized)}\n"
            "2) 返回严格 JSON：{\"action\": \"simulate|refuse|observe\", \"target\": \"<url或空>\", "
            "\"vuln_type\": \"<类型>\", \"severity\": \"Low|Medium|High\", \"rationale\": \"<理由>\", "
            "\"done\": false}。\n"
            "不要编造证据；无发现时 action=observe 且不要给 vuln_type。"
        )
        user = (
            f"step 定义：{json.dumps(step, ensure_ascii=False)}\n"
            f"context：{json.dumps(context, ensure_ascii=False)}"
        )
        return [{"role": "system", "content": system}, {"role": "user", "content": user}]

    async def _call_llm(self, messages: list[dict]) -> str:
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.2,
            "response_format": {"type": "json_object"},
        }
        if self._client is not None:
            resp = await self._client.post(f"{self.base_url}/chat/completions", json=payload)
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]
        import httpx  # 懒加载，离线环境不强制依赖

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{self.base_url}/chat/completions",
                json=payload,
                headers={"Authorization": f"Bearer {self.api_key}"},
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]

    async def decide(self, step: dict, context: dict, guard: ScopeGuard) -> AgentDecision:
        messages = self._messages(step, context, guard)
        raw = await self._call_llm(messages)
        data = _parse_json(raw)
        action = (data.get("action") or "observe").lower()
        target = data.get("target")
        if action == "refuse" or (target and not guard.allows(target)):
            return AgentDecision(
                action="refuse", target=target, finding=None,
                out_of_scope=bool(target), rationale=data.get("rationale", ""),
            )
        if action == "simulate" and data.get("vuln_type"):
            fid = f"FIND-{uuid.uuid4().hex[:8]}"
            finding = Finding(
                id=fid,
                vuln_type=str(data["vuln_type"]),
                severity=str(data.get("severity", "Medium")),
                url=target or "",
                detail={
                    "step": step.get("step"),
                    "agent": "llm",
                    "model": self.model,
                    "rationale": data.get("rationale"),
                },
                extracted_artifacts={"observed_step": step.get("step"), "agent": "llm"},
            )
            return AgentDecision(
                action="simulate", target=target, finding=finding,
                done=bool(data.get("done")), rationale=data.get("rationale", ""),
            )
        return AgentDecision(
            action="observe", target=target, finding=None, rationale=data.get("rationale", ""),
        )


def _parse_json(text: str) -> dict:
    """尽力从 LLM 输出中解析 JSON（容错 markdown 代码块/多余文本）。"""
    text = (text or "").strip()
    if not text:
        return {}
    try:
        return json.loads(text)
    except Exception:
        pass
    # 去 ```json ... ``` 围栏
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    if fenced:
        try:
            return json.loads(fenced.group(1))
        except Exception:
            pass
    # 退路：首个 { ... } 片段
    m = re.search(r"\{.*\}", text, re.S)
    if m:
        try:
            return json.loads(m.group(0))
        except Exception:
            pass
    return {}


def get_agent() -> BaseAgent:
    """按环境选择 Agent：配置了 DIGPOOL_LLM_API_KEY 用真实 LLMAgent，否则 DeterministicAgent 兜底。"""
    if os.getenv(ENV_API_KEY):
        return LLMAgent()
    return DeterministicAgent()


__all__ = [
    "AgentDecision",
    "ScopeGuard",
    "BaseAgent",
    "DeterministicAgent",
    "LLMAgent",
    "get_agent",
]

"""AIMatrixRunner —— `ai` 域的矩阵编排（E3）。

把「AI 风险」作为 `ai` 域接入 testflow 语义：**归属 → 执行 playbook → 门裁决 → 矩阵格结论**。
- 执行者：`llm`（复用 `core.ai_sec.prompt_injection.ProbeRunner`）/ `tool`（复用 agent_eval / rag_sec）/ `local`（确定性）。
- 门：复用 `_gates`（引擎优先，本地等价降级）。
- 结论：命中并入矩阵格 → `run_triage_gate` 准入 → `reported` / `needs_follow_up`（R3 全量原则，不静默）。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.ai_sec.ai_matrix._gates import gate_pre, run_triage_gate, uses_engine
from core.ai_sec.ai_matrix.adapter import to_matrix_finding
from core.ai_sec.ai_matrix.tagger import AI_DOMAIN, AIEndpointTagger

__all__ = ["AIMatrixRunner", "AIMatrixResult", "load_playbook"]

_PLAYBOOK_DIR = Path(__file__).parent / "playbooks"

# playbook 缺失 PyYAML 时的内嵌兜底（与 playbooks/ai.yaml 等价）
_EMBEDDED_PLAYBOOK: dict[str, Any] = {
    "domain": "ai",
    "steps": [
        {"id": "direct_injection", "executor": "llm", "probe_category": "direct"},
        {"id": "jailbreak_multiturn", "executor": "llm", "probe_category": "jailbreak"},
        {"id": "indirect_injection", "executor": "llm", "probe_category": "indirect"},
        {"id": "ai_rag_sec", "executor": "tool", "tool": "ai_rag_sec"},
        {"id": "ai_agent_eval", "executor": "tool", "tool": "ai_agent_eval"},
    ],
}


def load_playbook(domain: str = "ai") -> dict[str, Any]:
    """加载 `playbooks/{domain}.yaml`（无 PyYAML 时回退内嵌）。"""
    path = _PLAYBOOK_DIR / f"{domain}.yaml"
    if path.exists():
        try:
            import yaml

            with path.open(encoding="utf-8") as f:
                return yaml.safe_load(f) or _EMBEDDED_PLAYBOOK
        except Exception:
            pass
    return _EMBEDDED_PLAYBOOK


@dataclass
class AIMatrixResult:
    target_url: str = ""
    used_engine_gates: bool = False
    tagged: int = 0
    steps_run: list = field(default_factory=list)
    steps_skipped: list = field(default_factory=list)
    findings: list = field(default_factory=list)       # 原始 AIRiskFinding
    admitted: list = field(default_factory=list)        # 过门（矩阵 finding dict）
    blocked: list = field(default_factory=list)         # 被门阻断
    cells: list = field(default_factory=list)           # [{fp, domain, status}]

    def to_dict(self) -> dict:
        return {
            "target_url": self.target_url,
            "used_engine_gates": self.used_engine_gates,
            "tagged": self.tagged,
            "steps_run": self.steps_run,
            "steps_skipped": self.steps_skipped,
            "finding_count": len(self.findings),
            "admitted": len(self.admitted),
            "blocked": len(self.blocked),
            "cells": self.cells,
        }


class AIMatrixRunner:
    """把 `ai` 域接入矩阵的执行器。"""

    def __init__(self, tagger: AIEndpointTagger | None = None,
                 playbook: dict | None = None, responder: Any | None = None):
        self.tagger = tagger or AIEndpointTagger()
        self.playbook = playbook or load_playbook("ai")
        self.responder = responder

    async def run(self, target: Any, feature_points: Any = None) -> AIMatrixResult:
        result = AIMatrixResult(
            target_url=getattr(target, "url", ""),
            used_engine_gates=uses_engine(),
        )

        fps = list(feature_points or [])
        if fps:
            stats = self.tagger.tag(fps)
            result.tagged = stats["attributed"]
            result.cells = [
                {"fp": getattr(fp, "id", "?"), "domain": AI_DOMAIN, "status": "needs_follow_up"}
                for fp in fps
                if AI_DOMAIN in (getattr(fp, "risk_domains", None) or [])
            ]
        else:
            result.cells = [{"fp": "(target)", "domain": AI_DOMAIN, "status": "needs_follow_up"}]

        raw: list = []
        for step in self.playbook.get("steps", []):
            ok, reason = gate_pre(step)
            if not ok:
                result.steps_skipped.append({step.get("id", "?"): reason})
                continue
            try:
                findings = await self._exec_step(step, target)
            except Exception as exc:  # 单步失败不拖垮整体（显式记录）
                result.steps_skipped.append({step.get("id", "?"): str(exc)})
                continue
            result.steps_run.append(step.get("id", "?"))
            raw.extend(findings)

        matrix_findings = [to_matrix_finding(f, domain=AI_DOMAIN) for f in raw]
        admitted, blocked = run_triage_gate(matrix_findings)

        result.findings = raw
        result.admitted = admitted
        result.blocked = blocked
        if admitted:
            for c in result.cells:
                c["status"] = "reported"
        return result

    # ---- 三执行者 ----
    async def _exec_step(self, step: dict, target: Any) -> list:
        executor = step.get("executor")
        if executor == "llm":
            return await self._exec_llm(step, target)
        if executor == "tool":
            return await self._exec_tool(step, target)
        # local：需要响应上下文（如被动指纹），离线标记为未闭环（不静默）
        return []

    async def _exec_llm(self, step: dict, target: Any) -> list:
        from core.ai_sec.prompt_injection import ProbeRegistry, ProbeRunner

        reg = ProbeRegistry.load_builtin()
        category = step.get("probe_category")
        probes = reg.by_category(category) if category else reg.all()
        if not probes:
            return []
        runner = ProbeRunner(reg, responder=self.responder)
        results = await runner.run(target, probes=probes)
        return ProbeRunner.findings(results)

    async def _exec_tool(self, step: dict, target: Any) -> list:
        tool = step.get("tool")
        if tool == "ai_rag_sec":
            from core.ai_sec.rag_sec import RagSecurityScanner

            res = await RagSecurityScanner().scan(target, responder=self.responder)
            return list(res.findings)
        if tool == "ai_agent_eval":
            from core.ai_sec.agent_eval import AgentSecurityEvaluator

            res = await AgentSecurityEvaluator().evaluate(target, responder=self.responder)
            return list(res.findings)
        if tool == "skill_scan":
            # 需 skill 包路径（非 URL 目标），由 TargetType=skill 分支单独处理
            return []
        raise NotImplementedError(f"未注册的平台工具: {tool}")

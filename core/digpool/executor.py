"""工具执行器（Executor）：把治理裁决后的 ToolCall 派发给注册表工具，并转换结果为 Finding。

对齐 TechPlan §4.2 Executor 智能体 + §4.3 Tool 协议：调度 tools/ 注册的真实检测能力，
高风险工具受 governance 审批门约束（低自动 / 高人工）。
"""
from __future__ import annotations

import uuid
from typing import Any

from core.digpool.governance import Governance, GovernanceDecision
from core.digpool.loops.loop_controller import Finding
from core.digpool.tools.protocol import RiskLevel, ToolCall
from core.digpool.tools.registry import get_tool


def _to_finding(item: dict[str, Any], tool: str) -> Finding:
    """把工具返回的 finding dict 规范化为 LOOP 引擎的 Finding。

    兼容技能供应链扫描（name/check_type/file_path）与通用 schema。
    """
    return Finding(
        id=item.get("id") or f"FIND-{uuid.uuid4().hex[:8]}",
        vuln_type=item.get("name") or item.get("rule_id")
        or item.get("check_type") or item.get("vuln_type") or item.get("category") or "Generic",
        severity=str(item.get("severity", "Medium")),
        url=item.get("file_path") or item.get("file") or item.get("url") or item.get("asset") or "",
        detail={"tool": tool, **item},
        extracted_artifacts={"tool": tool},
    )


class ToolExecutor:
    """执行经治理裁决的工具调用。"""

    def __init__(self, governance: Governance | None = None) -> None:
        self.gov = governance or Governance()

    async def run(self, call: ToolCall) -> dict[str, Any]:
        tool = get_tool(call.tool)
        if tool is None:
            return {"tool": call.tool, "ok": False, "summary": "工具未注册", "findings": [], "meta": {}}

        # 1) 审批门（六维治理 · Approval）
        decision: GovernanceDecision = self.gov.screen(tool.name, tool.risk_level, call.args)
        if decision.needs_approval and not decision.allow:
            return {
                "tool": tool.name,
                "ok": False,
                "blocked_by_governance": True,
                "approval_ticket_id": decision.ticket.ticket_id if decision.ticket else None,
                "summary": decision.reason,
                "findings": [],
                "meta": {},
            }

        # 2) 熔断（重复执行 / 预算）—— 以 tool+args 指纹做重复检测
        rep = self.gov.check_repeat(f"{tool.name}:{sorted(call.args.items())}")
        if not rep.allow:
            return {"tool": tool.name, "ok": False, "blocked_by_governance": True,
                    "summary": rep.reason, "findings": [], "meta": {}}

        # 3) 派发真实工具
        result = tool.handler(call.args)
        findings = [_to_finding(f, tool.name) for f in result.get("findings", [])]
        result["findings"] = findings  # 替换为规范 Finding 对象
        return result


__all__ = ["ToolExecutor", "ToolCall", "RiskLevel"]

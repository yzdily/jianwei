"""六维治理（对齐 0912_DigPool_tech_analysis.md §2.4 与 AI_Demo_TechPlan §4.4）。

蛙池AI 用 Agentic Loop 统一管控六类治理维度；鉴微侧在 MVP 阶段落地最关键的两维：
- 审批 Approval：risk_level == high → 生成审批单、人工确认后才执行；low/medium 自动放行。
- 熔断 Circuit-break：预算（token/成本）超额、重复执行检测 → 中止。

其余四维（Goal / Scope / Budget 计量 / Acceptance 证据驱动）在 MVP 中以最小桩实现，
后续里程碑补全（见 MVP_GAP_ANALYSIS.md）。
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from core.digpool.tools.protocol import RiskLevel


@dataclass
class ApprovalTicket:
    """高风险工具调用的审批单。"""

    ticket_id: str
    tool: str
    args: dict
    reason: str
    status: str = "pending"  # pending | approved | rejected


@dataclass
class GovernanceDecision:
    """一次治理裁决结果。"""

    allow: bool
    needs_approval: bool
    ticket: ApprovalTicket | None = None
    reason: str = ""


class Governance:
    """六维治理最小实现：审批 + 熔断，其余维度留桩。"""

    def __init__(
        self,
        *,
        budget_tokens: int = 200_000,
        max_repeat: int = 3,
        auto_approve_high: bool = False,
    ) -> None:
        self.budget_tokens = budget_tokens
        self.spent_tokens = 0
        self.max_repeat = max_repeat
        self._seen_calls: dict[str, int] = {}
        self.auto_approve_high = auto_approve_high
        self.tickets: dict[str, ApprovalTicket] = {}

    # ---------- 审批 Approval ----------
    def screen(self, tool: str, risk_level: RiskLevel, args: dict) -> GovernanceDecision:
        """对一次工具调用做审批裁决。"""
        if risk_level == RiskLevel.HIGH and not self.auto_approve_high:
            ticket = ApprovalTicket(
                ticket_id=f"APR-{uuid.uuid4().hex[:8]}",
                tool=tool, args=args,
                reason="高风险工具需人工审批（蛙池AI：低自动 / 高人工）",
            )
            self.tickets[ticket.ticket_id] = ticket
            return GovernanceDecision(
                allow=False, needs_approval=True, ticket=ticket,
                reason="高风险，待人工审批",
            )
        return GovernanceDecision(allow=True, needs_approval=False, reason="低风险自动放行")

    def approve(self, ticket_id: str, *, approved: bool) -> ApprovalTicket | None:
        t = self.tickets.get(ticket_id)
        if t is None:
            return None
        t.status = "approved" if approved else "rejected"
        return t

    # ---------- 熔断 Circuit-break ----------
    def charge(self, tokens: int) -> GovernanceDecision:
        """预算扣减；超额则熔断。"""
        self.spent_tokens += tokens
        if self.spent_tokens > self.budget_tokens:
            return GovernanceDecision(allow=False, needs_approval=False, reason="预算超额，已熔断")
        return GovernanceDecision(allow=True, needs_approval=False, reason="预算充足")

    def check_repeat(self, key: str) -> GovernanceDecision:
        """重复执行检测：同一调用超过 max_repeat 次则熔断。"""
        self._seen_calls[key] = self._seen_calls.get(key, 0) + 1
        if self._seen_calls[key] > self.max_repeat:
            return GovernanceDecision(allow=False, needs_approval=False, reason=f"重复执行超过 {self.max_repeat} 次，已熔断")
        return GovernanceDecision(allow=True, needs_approval=False, reason="重复度正常")


__all__ = ["Governance", "ApprovalTicket", "GovernanceDecision", "RiskLevel"]

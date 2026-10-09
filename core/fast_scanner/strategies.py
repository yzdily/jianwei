"""双轴扫描策略工厂：目标类型 × 测试策略 → 启用的 check 列表 + target 上下文注入。

对应 MASTER_PLAN §11.1。FastScanner 不硬编码任何 check 细节，
只通过 StrategyPlan.enabled_rules 决定派发哪些 `_check_{rule}`，
并把目标类型相关的上下文（llm / skill_source）注入 target.extra。

设计要点（零侵入）：
- 新增专项扫描只需：(1) 写一个 `_ChecksXxx` mixin 提供 `_check_xxx`；
  (2) 在此工厂把 "xxx" 加入对应 TargetType 的 enabled_rules。
  FastScanner 对未实现的 check 自动跳过，不影响既有流程。
- LLM / AGENT / RAG 类型默认启用 llm_vuln（MASTER_PLAN §11.1 要求）。
- SKILL 类型默认启用 skill_scan，且不触发 llm_vuln（避免把供应链包当 LLM 打）。
"""
from __future__ import annotations

from core.fast_scanner.models import (
    ScanMode,
    ScanTarget,
    StrategyPlan,
    TargetType,
)


def _infer_type(target: ScanTarget) -> TargetType:
    """AUTO 模式下根据 target.extra 特征推断真实类型。"""
    if target.extra.get("skill_source") or target.source:
        return TargetType.SKILL
    if target.extra.get("llm"):
        return TargetType.LLM
    # 默认按 Web 处理（尚无 Web 专项 mixin 时 enabled_rules 为空，安全跳过）
    return TargetType.WEB


def get_scan_strategy(
    target_type: str | TargetType,
    strategy: str | ScanMode = "standard",
    target: ScanTarget | None = None,
) -> StrategyPlan:
    """计算双轴策略。

    参数：
      target_type  字符串或 TargetType（"auto" 时结合 target 特征推断）
      strategy     字符串或 ScanMode（兼容 FAST/DEEP/SMART 别名）
      target       用于 AUTO 推断与上下文注入
    返回 StrategyPlan（含 enabled_rules 与 apply() 注入逻辑）。
    """
    ttype = (
        target_type if isinstance(target_type, TargetType)
        else TargetType.parse(str(target_type))
    )
    mode = (
        strategy if isinstance(strategy, ScanMode)
        else ScanMode.parse(str(strategy))
    )

    if ttype == TargetType.AUTO and target is not None:
        ttype = _infer_type(target)

    # ---- 按目标类型组装 enabled_rules + 上下文注入 ----
    if ttype == TargetType.SKILL:
        src = (target.source if target else "") or (target.extra.get("skill_source") if target else "")
        plan = StrategyPlan(
            target_type=ttype, mode=mode, enabled_rules=["skill_scan"],
            _prepare=lambda t: t.inject_skill(src or t.url),
        )
        return plan

    if ttype in (TargetType.LLM, TargetType.AGENT, TargetType.RAG):
        # 主动模式才注入攻击载荷；被动模式仅观察（_check_llm_vuln 仍会跑探测）
        llm_mode = "active" if mode.is_active() else "passive"
        plan = StrategyPlan(
            target_type=ttype, mode=mode, enabled_rules=["llm_vuln"],
            _prepare=lambda t: t.inject_llm(
                mode=llm_mode,
                model=t.extra.get("llm", {}).get("model", "default"),
                tools=t.extra.get("llm", {}).get("tools"),
            ),
        )
        return plan

    # WEB / API / 其它：尚无专项 mixin；保留 enabled_rules 为空（零侵入跳过）。
    # 未来接入 _ChecksInjection / _ChecksServer 时在此追加即可。
    plan = StrategyPlan(target_type=ttype, mode=mode, enabled_rules=[])
    return plan

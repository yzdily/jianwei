"""FastScanner —— 鉴微平台层扫描引擎（零侵入分发）。

通过多重继承 mixin 组合各检测能力，沿用 xuanjian `getattr(self, f"_check_{rule}")`
动态分发机制。新模式只改变 `enabled_rules`（由 core.scan_strategies 双轴工厂产出），
不修改既有检测逻辑（MASTER_PLAN §12.2 / §14 C1）。

    class FastScanner(_ChecksWeb, _ChecksLLM, _ChecksSkill):
        ...
"""
from __future__ import annotations

import inspect
from typing import Iterable

import asyncio

from core.log import get_logger
from core.scan_strategies import (
    TargetType, TestStrategy, get_scan_strategy, ScanConfig,
)
from ._models import ScanTarget, VulnFinding
from ._checks_web import _ChecksWeb
from ._checks_llm import _ChecksLLM
from ._checks_skill import _ChecksSkill

log = get_logger("fast_scanner.engine")


class FastScanner(_ChecksWeb, _ChecksLLM, _ChecksSkill):
    """扫描引擎：按双轴策略组装规则并逐条分发。

    子类化各 _Checks* mixin 获得 `_check_<rule>` 方法。
    """

    def __init__(self):
        self._strategy: str = TestStrategy.STANDARD.value
        self._scan_config: ScanConfig | None = None

    async def scan_target(
        self,
        target: ScanTarget,
        strategy: str | TestStrategy = TestStrategy.STANDARD,
        target_type: str | TargetType | None = None,
    ) -> list[VulnFinding]:
        """对单个目标执行扫描。

        Args:
            target: 通用扫描目标。
            strategy: 测试策略（默认 standard）。
            target_type: 目标类型（缺省时用 target.target_type）。

        Returns:
            归一化的 VulnFinding 列表。
        """
        tt = target_type or target.target_type or TargetType.WEB.value
        config = get_scan_strategy(tt, strategy)
        self._strategy = config.strategy.value
        self._scan_config = config

        findings: list[VulnFinding] = []
        for rule in config.enabled_rules:
            handler = getattr(self, f"_check_{rule}", None)
            if handler is None:
                log.debug(f"skip rule (no handler in platform layer): {rule}")
                continue
            try:
                result = handler(target)
                if inspect.isawaitable(result):
                    result = await result
                if result:
                    findings.extend(result)
            except Exception as e:  # 单条规则失败不拖垮整体
                log.error(f"rule {rule} failed: {e}")

        log.info(
            f"scan done: target={target.url or target.skill_meta.get('path','')} "
            f"rules={config.enabled_rules} findings={len(findings)}"
        )
        return findings

    def scan_target_sync(
        self,
        target: ScanTarget,
        strategy: str | TestStrategy = TestStrategy.STANDARD,
        target_type: str | TargetType | None = None,
    ) -> list[VulnFinding]:
        """同步封装（CLI / 测试用）。"""
        return asyncio.run(self.scan_target(target, strategy, target_type))


def scan(
    target: ScanTarget,
    strategy: str | TestStrategy = TestStrategy.STANDARD,
    target_type: str | TargetType | None = None,
) -> list[VulnFinding]:
    """模块级便捷入口。"""
    return FastScanner().scan_target_sync(target, strategy, target_type)


__all__ = ["FastScanner", "scan", "ScanTarget", "VulnFinding"]

"""分析器注册表 —— 仿 SkillSpector 的 analyzer 插件机制。

每个 analyzer 是 callable(SkillTarget, strategy) -> list[SkillFinding]；
registry 负责按策略装配并分发。skill_scan 包内部的 analyzers 子模块在此注册。
"""
from __future__ import annotations

from .models import SkillFinding, SkillTarget, SkillStrategy

# name -> analyzer callable
_REGISTRY: dict[str, callable] = {}

# 各策略启用的分析器
#   standard : 静态正则 + AST + 供应链(OSV) + YARA 签名
#   redteam  : standard + LLM 语义分析（意图检测 + 降误报）
#   compliance: standard（差距清单在 markdown 报告中体现）
_STRATEGY_ANALYZERS: dict[str, list[str]] = {
    SkillStrategy.PASSIVE.value: [],                 # 仅清单，无分析器
    SkillStrategy.STANDARD.value: ["pattern", "ast_behavior", "supply_chain", "yara_scan"],
    SkillStrategy.REDTEAM.value: ["pattern", "ast_behavior", "supply_chain", "yara_scan", "semantic"],
    SkillStrategy.COMPLIANCE.value: ["pattern", "ast_behavior", "supply_chain", "yara_scan"],
}


def register(name: str, analyzer: callable) -> None:
    _REGISTRY[name] = analyzer


def get(name: str) -> callable | None:
    return _REGISTRY.get(name)


def enabled_for(strategy: str) -> list[str]:
    return _STRATEGY_ANALYZERS.get(strategy, _STRATEGY_ANALYZERS[SkillStrategy.STANDARD.value])


def run(target: SkillTarget, strategy: str) -> tuple[list[SkillFinding], list[str]]:
    """运行当前策略下所有已注册分析器。

    Returns:
        (findings, errors)
    """
    findings: list[SkillFinding] = []
    errors: list[str] = []
    for name in enabled_for(strategy):
        fn = _REGISTRY.get(name)
        if fn is None:
            continue
        try:
            findings.extend(fn(target, strategy))
        except Exception as e:
            errors.append(f"analyzer[{name}] failed: {e}")
    return findings, errors


# ---- 自动注册 analyzers 子模块的分析器 ----
def _autoload() -> None:
    from .analyzers import pattern, ast_behavior, supply_chain, yara_scan, semantic
    register("pattern", pattern.analyze)
    register("ast_behavior", ast_behavior.analyze)
    register("supply_chain", supply_chain.analyze)
    register("yara_scan", yara_scan.analyze)
    register("semantic", semantic.analyze)


_autoload()

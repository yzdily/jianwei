"""skill_scan 分析器注册表（仿 SkillSpector 注册表模式，设计 §3.2）。"""
from __future__ import annotations

from .base import Analyzer, FileEntry, ScanContext, SkillFinding

# 注册的分析器（顺序即执行顺序）
_REGISTRY: list[Analyzer] = []


def register(analyzer: Analyzer) -> None:
    """注册一个分析器实例。"""
    if not any(a.name == analyzer.name for a in _REGISTRY):
        _REGISTRY.append(analyzer)


def register_all() -> None:
    """注册全部内置分析器。"""
    from .pattern import PatternAnalyzer
    from .ast_behavior import ASTBehaviorAnalyzer
    from .supply_chain import SupplyChainAnalyzer
    from .semantic import SemanticAnalyzer
    from .yara_scan import YaraScanAnalyzer

    for cls in (
        PatternAnalyzer, ASTBehaviorAnalyzer, SupplyChainAnalyzer,
        SemanticAnalyzer, YaraScanAnalyzer,
    ):
        register(cls())


def run_enabled(files: list[FileEntry], ctx: ScanContext) -> list[SkillFinding]:
    """按策略运行所有启用分析器，汇总发现。"""
    if not _REGISTRY:
        register_all()
    out: list[SkillFinding] = []
    for analyzer in _REGISTRY:
        if ctx.strategy not in analyzer.enabled_strategies:
            continue
        try:
            out.extend(analyzer.analyze(files, ctx))
        except Exception as e:  # 单分析器失败不拖垮整体
            from core.log import get_logger
            get_logger("skill_scan.registry").error(f"analyzer {analyzer.name} failed: {e}")
    return out


__all__ = ["register", "register_all", "run_enabled"]

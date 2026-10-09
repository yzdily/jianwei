"""DigPool Tool & Data 层（对齐 0912_XuanJian_AI_Demo_TechPlan.md §4.3）。

对标蛙池AI 的 DigPool Hub（Skills / Tools / MCP）。在鉴微侧，把平台层已有的检测能力
（skill_scan 供应链扫描、llm_top10 漏洞扫描、sec_shield 护栏等）桥接为统一 Tool 契约，
供 Agentic Loop 的 Executor 调度。

依赖红线：本层仅依赖 core/ 与标准库，不引入新第三方包。
"""
from .protocol import RiskLevel, Tool, ToolCall
from .registry import (
    ToolRegistry,
    get_registry,
    register_tool,
    get_tool,
    list_tools,
    register_builtins,
)

__all__ = [
    "RiskLevel",
    "Tool",
    "ToolCall",
    "ToolRegistry",
    "get_registry",
    "register_tool",
    "get_tool",
    "list_tools",
    "register_builtins",
]

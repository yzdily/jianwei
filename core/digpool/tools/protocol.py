"""Tool 统一契约（对齐蛙池AI Tool schema）。

用标准库 dataclass 实现（不依赖 pydantic，保证零第三方依赖可跑）。
risk_level 直接映射到治理审批门（见 governance.py）：low/medium 自动放行，high 进人工审批。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class Tool:
    """一个可调用的安全工具（curated skill / 内置能力 / MCP 桥）。"""

    name: str                      # 唯一标识，如 "skill-scan"
    description: str               # 自然语言描述，供 LLM/Planner 选择
    input_schema: dict             # JSON Schema 风格参数定义
    risk_level: RiskLevel          # 映射到审批门
    handler: Callable[..., dict]   # 实际执行函数，返回统一结果 dict
    source: str = "builtin"        # builtin | skill | mcp


@dataclass
class ToolCall:
    """一次工具调用意图。"""

    tool: str
    args: dict = field(default_factory=dict)
    risk_level: RiskLevel = RiskLevel.LOW
    approval_ticket_id: str | None = None  # 高风险时挂审批单


# 工具执行统一返回结构（约定）：
# {
#   "tool": str,
#   "ok": bool,
#   "summary": str,
#   "findings": list[dict],      # 可转成 loops.loop_controller.Finding
#   "meta": dict,                # 附加信息（score / severity / exit_code ...）
#   "degraded": bool = False,    # 因依赖缺失而降级（如 llm-top10 缺 openai）
# }

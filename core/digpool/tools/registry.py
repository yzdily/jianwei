"""工具注册表（桥接 jianwei 既有检测能力为 Tool 来源）。"""
from __future__ import annotations

from typing import Optional

from .protocol import Tool


class ToolRegistry:
    """内存工具注册表：登记 curated skill / 内置能力 / MCP 桥。"""

    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> Tool:
        self._tools[tool.name] = tool
        return tool

    def get(self, name: str) -> Optional[Tool]:
        return self._tools.get(name)

    def list(self) -> list[Tool]:
        return list(self._tools.values())

    def names(self) -> list[str]:
        return sorted(self._tools.keys())


# 进程级默认注册表
_DEFAULT: ToolRegistry | None = None


def get_registry() -> ToolRegistry:
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = ToolRegistry()
        # 延迟登记内置工具，避免循环导入
        from . import builtins as _b  # noqa: F401
        _b.register_all(_DEFAULT)
    return _DEFAULT


def register_tool(tool: Tool) -> Tool:
    return get_registry().register(tool)


def get_tool(name: str) -> Optional[Tool]:
    return get_registry().get(name)


def list_tools() -> list[Tool]:
    return get_registry().list()


def register_builtins(registry: ToolRegistry | None = None) -> ToolRegistry:
    reg = registry or get_registry()
    from . import builtins as _b
    _b.register_all(reg)
    return reg

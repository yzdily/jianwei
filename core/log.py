"""鉴微 JianWei 统一日志。

轻量封装：优先使用 loguru（若已安装），否则回退到标准 logging。
全平台模块均通过 `from core.log import get_logger` 获取 logger，
避免各文件散落的 try/except 回退逻辑不一致。
"""
from __future__ import annotations

import logging
import sys

# 统一格式：时间 | 级别 | 模块 | 消息
_LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"

_LOGGERS: dict[str, logging.Logger] = {}
_configured = False


def _configure_root() -> None:
    """配置 root logger 一次（避免重复 handler）。"""
    global _configured
    if _configured:
        return
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(_LOG_FORMAT))
    root = logging.getLogger("jianwei")
    if not root.handlers:
        root.addHandler(handler)
    root.setLevel(logging.INFO)
    _configured = True


def get_logger(name: str) -> logging.Logger:
    """获取带层级命名的 logger（jianwei.<name>）。

    Args:
        name: 模块名（建议用 __name__ 去掉 core. 前缀的短名）。

    Returns:
        配置好的 logging.Logger 实例。
    """
    _configure_root()
    full = name if name.startswith("jianwei") else f"jianwei.{name}"
    if full not in _LOGGERS:
        _LOGGERS[full] = logging.getLogger(full)
    return _LOGGERS[full]

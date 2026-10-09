"""鉴微 LLM 安全核心包 — 攻击库 / 判定引擎 / 多轮驱动 / 工具滥用模拟。

本包是鉴微平台 L2 层的核心能力，对应 818 设计文档 §3.2。
所有模块均为平台层净新增，不修改玄鉴引擎。

依赖纪律（对齐 DigPool 零依赖可跑目标）：
- `attacks` 依赖 `httpx`、`judge` 依赖 `openai` 等第三方包，可能在离线/未安装环境缺失。
- 这些重依赖模块**不**在包初始化时 eager import，改为 PEP 562 模块级 `__getattr__`
  懒加载：包本身（含 stdlib-only 的 `skill_scan`）在无 httpx/openai 时也能正常导入。
- 仅当代码真正用到 `fire_attack`/`judge_response` 等时才触发对应子模块导入；
  若环境确实缺依赖，会在调用点给出清晰报错，而不是拖累整个包导入失败。
"""
from __future__ import annotations

import importlib

_LAZY = {
    "fire_attack": (".attacks", "fire_attack"),
    "fill_vars": (".attacks", "fill_vars"),
    "AttackResult": (".attacks", "AttackResult"),
    "judge_response": (".judge", "judge_response"),
    "llm_judge": (".judge", "llm_judge"),
    "MultiTurnDriver": (".conversation", "MultiTurnDriver"),
    "ScoringCard": (".scoring", "ScoringCard"),
    "make_trace_id": (".scoring", "make_trace_id"),
    "_ChecksLLM": ("._checks_llm", "_ChecksLLM"),
}


def __getattr__(name: str):
    spec = _LAZY.get(name)
    if spec is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    mod = importlib.import_module(spec[0], __name__)
    return getattr(mod, spec[1])


__all__ = list(_LAZY.keys())

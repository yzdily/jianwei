"""鉴微 DigPool 工作台（平台层 L2+ 入口，对标斗象蛙池AI / DigPool AI）。

落点：鉴微独立仓库（github.com/yzdily/jianwei），不进入玄鉴 core。
AI 原生模块（LLM/Agent/RAG/对话工作台）按 ARCHITECTURE.md 归鉴微平台层。
"""
from __future__ import annotations

from .agent import (
    AgentDecision,
    BaseAgent,
    DeterministicAgent,
    LLMAgent,
    ScopeGuard,
    get_agent,
)
from .agents import (
    PHASES,
    BasePlanner,
    BaseValidator,
    DeterministicPlanner,
    HarmValidator,
    LLMPlanner,
    Plan,
    Reporter,
    StubValidator,
    SubTask,
    ValidationResult,
    VERDICT_CONFIRMED,
    VERDICT_REJECTED,
    VERDICT_SUSPECT,
    get_planner,
    get_validator,
)
from .memory import MemoryStore
from .core_link import (
    CORE_LINKED,
    CoreBackend,
    StubCore,
    XuanjianCore,
    get_core_backend,
    get_loop_controller,
)
from .ingest import ComplianceCertSource, ProxyTrafficSource
from .scope import Scope, ScopeUpdate, TrafficCorpus
from .session import DigPoolEvent, DigPoolSession, SessionPhase

__all__ = [
    "DigPoolSession",
    "DigPoolEvent",
    "SessionPhase",
    "Scope",
    "ScopeUpdate",
    "TrafficCorpus",
    "CORE_LINKED",
    "CoreBackend",
    "StubCore",
    "XuanjianCore",
    "get_core_backend",
    "get_loop_controller",
    "BaseAgent",
    "DeterministicAgent",
    "LLMAgent",
    "AgentDecision",
    "ScopeGuard",
    "get_agent",
    "ProxyTrafficSource",
    "ComplianceCertSource",
    # M1/M3/M4 闭环组件
    "Plan",
    "SubTask",
    "PHASES",
    "BasePlanner",
    "DeterministicPlanner",
    "LLMPlanner",
    "get_planner",
    "Reporter",
    "ValidationResult",
    "BaseValidator",
    "StubValidator",
    "HarmValidator",
    "get_validator",
    "VERDICT_CONFIRMED",
    "VERDICT_SUSPECT",
    "VERDICT_REJECTED",
    "MemoryStore",
]

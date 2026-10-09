"""鉴微双轴扫描策略 —— MASTER_PLAN §12 + Skill供应链扫描 §3.1。

把"单深度滑块"重构为两正交轴：

  TargetType  目标类型：web / api / llm_app / agent / rag / skill
  TestStrategy 测试策略：passive / standard / redteam / compliance

`get_scan_strategy(target_type, strategy)` 返回 `ScanConfig`，含 `enabled_rules`
（零侵入接入 FastScanner 的 `getattr(self, f"_check_{rule}")` 分发机制）。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from core.log import get_logger

log = get_logger("scan_strategies")


class TargetType(str, Enum):
    """被测对象类型 —— 决定启用哪套规则与攻击库。"""
    __test__ = False  # 避免 pytest 将其误当作测试类收集

    WEB = "web"          # 传统 Web 应用
    API = "api"          # API 接口
    LLM_APP = "llm_app"  # LLM 应用 / 对话补全端点
    AGENT = "agent"      # Agent / MCP 工具面
    RAG = "rag"          # RAG 知识库
    SKILL = "skill"      # Agent 技能包 / MCP server 包（静态供应链扫描）


class TestStrategy(str, Enum):
    """测试策略 —— 打多狠、是否主动发射对抗 payload。"""
    __test__ = False  # 避免 pytest 将其误当作测试类收集

    PASSIVE = "passive"          # 被动探测：仅资产发现 + 特征识别
    STANDARD = "standard"        # 标准：已知规则全量 + 确定性判定
    REDTEAM = "redteam"          # 主动红队：多轮越狱 + 工具滥用 + LLM-judge
    COMPLIANCE = "compliance"    # 合规对照：等保/OWASP/ATLAS 差距清单


# 传统 Web 规则（沿用玄鉴引擎既有 15 条；此处列出鉴微平台层管理的集合）
_WEB_RULES = [
    "sql_injection", "xss", "command_injection", "path_traversal",
    "ssrf", "xxe", "auth_bypass", "idors", "csrf", "jwt",
]
# LLM 专项 13 check（LLMVault 10 类 + Agent/MCP/RAG 3 新面，见 LLM扫描器 §1.7）
_LLM_RULES = ["llm_vuln"]


@dataclass
class ScanConfig:
    """一次扫描的策略组装结果。"""

    target_type: TargetType
    strategy: TestStrategy
    enabled_rules: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target_type": self.target_type.value,
            "strategy": self.strategy.value,
            "enabled_rules": self.enabled_rules,
            "notes": self.notes,
        }


# skill 目标的"策略轴"语义重解释（不开主动攻击，仅调节静态分析深度）
_SKILL_STRATEGY_NOTES = {
    TestStrategy.PASSIVE: "仅做文件清单 + 元数据 + 依赖清单（info 级）",
    TestStrategy.STANDARD: "静态正则 + AST + OSV 供应链（默认）",
    TestStrategy.REDTEAM: "在 standard 基础上再加 LLM 语义分析（降误报、出可读解释）",
    TestStrategy.COMPLIANCE: "对照 OWASP LLM Top 10 / MITRE ATLAS 出差距清单",
}


def get_scan_strategy(
    target_type: str | TargetType,
    strategy: str | TestStrategy = TestStrategy.STANDARD,
) -> ScanConfig:
    """双轴策略工厂 —— 返回该组合应启用的规则集。

    Args:
        target_type: 目标类型（字符串或 TargetType）。
        strategy: 测试策略（字符串或 TestStrategy），默认 standard。

    Returns:
        ScanConfig，含 enabled_rules。

    组装规则：
        - web / api      → 传统 Web 规则
        - llm_app/agent/rag → 传统 Web 规则 + llm_vuln
        - skill          → skill_scan（静态供应链，不触发 llm_vuln）
        - passive        → 仅资产发现类（info），不发射攻击 payload
        - redteam        → 追加多轮驱动器 + 工具滥用模拟 + LLM-judge 标记
    """
    tt = TargetType(target_type) if not isinstance(target_type, TargetType) else target_type
    st = TestStrategy(strategy) if not isinstance(strategy, TestStrategy) else strategy

    rules: list[str] = []
    notes: list[str] = []

    if tt == TargetType.SKILL:
        # 静态供应链扫描：仅 skill_scan，与运行时端点扫描互斥
        rules = ["skill_scan"]
        notes.append(_SKILL_STRATEGY_NOTES.get(st, ""))
        return ScanConfig(target_type=tt, strategy=st, enabled_rules=rules, notes=notes)

    # 传统目标
    if tt in (TargetType.WEB, TargetType.API):
        rules = list(_WEB_RULES)
    else:  # llm_app / agent / rag → Web 规则 + LLM 专项
        rules = list(_WEB_RULES) + list(_LLM_RULES)
        notes.append(f"{tt.value} 类型默认启用 llm_vuln（OWASP LLM Top 10 专项）")

    if st == TestStrategy.PASSIVE:
        # 被动：仅资产发现，去掉主动攻击类规则
        rules = ["asset_discovery"]
        notes.append("passive：仅资产发现 + 特征识别，不发射攻击 payload")
    elif st == TestStrategy.REDTEAM:
        notes.append("redteam：启用多轮驱动器 + 工具滥用模拟 + LLM-judge 二次确认")
    elif st == TestStrategy.COMPLIANCE:
        notes.append("compliance：按等保 / OWASP / ATLAS 对照产出差距清单")

    return ScanConfig(target_type=tt, strategy=st, enabled_rules=rules, notes=notes)

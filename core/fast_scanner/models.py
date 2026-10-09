"""FastScanner 统一数据模型与双轴策略类型。

对应 MASTER_PLAN §11（扫描模式双轴重设计：目标类型 × 测试策略）。
这里把"理想态"落成真实可运行模型：

- TargetType：目标类型轴（Web / API / LLM 应用 / Agent / RAG / Skill / 自动）
- ScanMode：测试策略轴（被动 / 标准 / 红队 / 合规）

FastScanner.scan_target 只消费 StrategyPlan.enabled_rules，
并经 getattr(self, f"_check_{rule}") 把规则派发给对应 _ChecksXxx mixin，
缺失的 check 安全跳过 —— 这是零侵入集成的核心约束（见 _engine.py）。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable


class TargetType(str, Enum):
    """目标类型轴（双轴之一）。"""
    WEB = "web"
    API = "api"
    LLM = "llm"          # LLM 应用（聊天/补全接口）
    AGENT = "agent"      # 自主 Agent（内部含 LLM）
    RAG = "rag"          # 检索增强生成（内部含 LLM + 知识库）
    SKILL = "skill"      # Skill / 供应链静态包（本地目录/zip/单文件）
    AUTO = "auto"        # 由 FastScanner 按特征推断

    @classmethod
    def parse(cls, value: str) -> "TargetType":
        try:
            return cls(value)
        except ValueError:
            return cls.AUTO


class ScanMode(str, Enum):
    """测试策略轴（双轴之二）。

    兼容 MASTER_PLAN §11 旧命名别名：
      FAST  -> PASSIVE（最快、仅指纹/被动）
      STANDARD -> STANDARD
      DEEP / SMART -> REDTEAM
    """
    PASSIVE = "passive"
    STANDARD = "standard"
    REDTEAM = "redteam"
    COMPLIANCE = "compliance"

    @classmethod
    def parse(cls, value: str) -> "ScanMode":
        if isinstance(value, cls):
            return value
        v = (value or "").lower()
        # 先尝试直接枚举值匹配（passive/standard/redteam/compliance）
        try:
            return cls(v)
        except ValueError:
            pass
        # 再走 MASTER_PLAN §11 旧命名别名
        alias = {
            "fast": cls.PASSIVE,
            "quick": cls.PASSIVE,
            "deep": cls.REDTEAM,
            "smart": cls.REDTEAM,
            "red_team": cls.REDTEAM,
        }
        return alias.get(v, cls.STANDARD)

    def is_active(self) -> bool:
        """是否为主动测试（会发起攻击载荷）。被动模式仅观察，不注入。"""
        return self in (ScanMode.STANDARD, ScanMode.REDTEAM)


@dataclass
class ScanTarget:
    """通用扫描目标。

    字段语义：
      url         目标地址（LLM 聊天接口 / Web 站点 / Agent 端点）
      headers     请求头（含鉴权 Bearer / Cookie）
      method      默认 POST（LLM/Agent）或 GET（Web 指纹）
      body        可选请求体模板（Agent/RAG 触发）
      extra       资产发现阶段填充的上下文（llm / skill_source / sitemap 等）
      target_type 目标类型（默认 AUTO，由策略工厂推断）
      source      本地路径（仅 SKILL 类型：目录/zip/单文件）
    """
    url: str = ""
    target_type: TargetType = TargetType.AUTO
    headers: dict = field(default_factory=dict)
    method: str = "POST"
    body: Any = None
    source: str = ""                     # SKILL 类型本地路径
    extra: dict = field(default_factory=dict)

    def inject_llm(self, mode: str, model: str = "default",
                   tools: list | None = None, chat_schema: bool = True,
                   auth: str | None = None) -> None:
        """资产发现阶段 / 策略工厂给目标打 LLM 上下文标签。"""
        self.extra.setdefault("llm", {})
        self.extra["llm"].update({
            "mode": mode,
            "model": model,
            "tools": tools or [],
            "chat_schema": chat_schema,
            "auth": auth,
        })

    def inject_skill(self, source: str) -> None:
        self.extra["skill_source"] = source
        if not self.source:
            self.source = source


@dataclass
class StrategyPlan:
    """双轴策略计算结果：决定启用哪些 check + 如何准备 target。"""
    target_type: TargetType
    mode: ScanMode
    enabled_rules: list[str] = field(default_factory=list)
    _prepare: Callable[[ScanTarget], None] | None = None

    def apply(self, target: ScanTarget) -> None:
        """把本策略要注入的上下文写到 target.extra。"""
        if self._prepare is not None:
            self._prepare(target)


@dataclass
class ScanResult:
    """FastScanner 统一扫描结果（异构 findings + 统一 AIRiskFinding 回流）。"""
    target: str
    target_type: str
    strategy: str
    findings: list = field(default_factory=list)        # 混合：AIRiskFinding / SkillFinding ...
    ai_risk_findings: list = field(default_factory=list)  # 统一回流后的 AIRiskFinding
    rules_run: list = field(default_factory=list)
    timed_out: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    elapsed: float = 0.0

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "target_type": self.target_type,
            "strategy": self.strategy,
            "finding_count": len(self.findings),
            "ai_risk_count": len(self.ai_risk_findings),
            "rules_run": self.rules_run,
            "timed_out": self.timed_out,
            "errors": self.errors,
            "elapsed": round(self.elapsed, 3),
            "findings": [
                getattr(f, "to_dict", lambda: _as_dict(f))()
                for f in self.findings
            ],
        }


def _as_dict(obj: Any) -> dict:
    """兜底序列化：AIRiskFinding 等无 to_dict 的统一字段抽取。"""
    d = {}
    for k in ("owasp", "vuln_type", "severity", "title", "url", "detail",
              "evidence", "file_path", "line", "snippet", "recommendation"):
        v = getattr(obj, k, None)
        if v is not None:
            d[k] = v
    return d or {"raw": str(obj)}

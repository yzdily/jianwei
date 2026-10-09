"""鉴微 AI 风险统一数据模型（PD9）。

供 L2-L5 共用，避免各层各自造对象。
对应 MASTER_PLAN §5.4 PA3 统一 AI 风险 schema。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EvidenceQuality(str, Enum):
    BODY_CONFIRMED = "body_confirmed"
    HEADER_ONLY = "header_only"
    CONTENT_MATCH = "content_match"


class OWASPLLMCategory(str, Enum):
    LLM01 = "LLM01"  # 提示注入
    LLM02 = "LLM02"  # 敏感信息泄露
    LLM03 = "LLM03"  # 供应链漏洞
    LLM04 = "LLM04"  # 数据与模型投毒
    LLM05 = "LLM05"  # 输出处理不当
    LLM06 = "LLM06"  # 过度代理
    LLM07 = "LLM07"  # 系统提示泄露
    LLM08 = "LLM08"  # 向量库越权
    LLM09 = "LLM09"  # 错误/误导信息
    LLM10 = "LLM10"  # 失控消耗
    AGENT = "AGENT"  # Agent 编排逃逸（新增）
    MCP = "MCP"      # MCP 工具链滥用（新增）
    RAG = "RAG"      # RAG 投毒（新增）


@dataclass
class AIRiskFinding:
    """AI 风险发现 — 统一 schema，供 L2-L5 共用。"""
    owasp: str
    vuln_type: str
    severity: str
    url: str
    detail: str
    evidence: str = ""
    payload: str = ""
    fix_suggestion: str = ""
    confidence: float = 0.0
    evidence_quality: str = ""
    trace_id: str = ""
    rule_tag: str = ""
    attack_turns: list[dict] = field(default_factory=list)
    response_snippet: str = ""

    def to_dict(self) -> dict:
        return {
            "owasp": self.owasp,
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "url": self.url,
            "detail": self.detail,
            "evidence": self.evidence[:500],
            "payload": self.payload[:200],
            "fix_suggestion": self.fix_suggestion,
            "confidence": self.confidence,
            "evidence_quality": self.evidence_quality,
            "trace_id": self.trace_id,
            "rule_tag": self.rule_tag,
            "response_snippet": self.response_snippet[:300],
        }

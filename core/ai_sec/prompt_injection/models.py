"""Prompt 注入测试集 — 数据模型。

设计纪律（见《鉴微优化方案》§2）：
- **不重写检测逻辑**：Probe 归一化为引擎级 `fire_attack` / `judge_response` 认得的 rule dict
  （`to_rule()`），运行器直接复用 `core.llm_security._probe.run_probe_outcome`。
- **数据即探针**：新增探针只追加数据，不改运行器。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# 四类探针（对应 OWASP LLM01 的直接/间接/越狱/多模态注入面）
CATEGORIES = ("direct", "indirect", "jailbreak", "multimodal")


@dataclass
class Probe:
    """一条注入探针（归一化模型）。

    Attributes:
        id: 稳定唯一 id（如 `pi-direct-001`），供去重与报告引用。
        category: direct / indirect / jailbreak / multimodal。
        turns: 多轮对话序列 `[{"role": "...", "content": "..."}]`（单轮即长度 1）。
        match: 命中判定规则 `[{"pattern": regex, "in": response|tool_result, "flags": "IGNORECASE"}]`。
        owasp: OWASP LLM 类别（LLM01 / LLM06 / LLM07 / LLM08 …）。
        severity: critical / high / medium / low。
        description: 人类可读描述（写入 finding.detail）。
        fix: 修复建议（写入 finding.fix_suggestion）。
        check: 归一化的平台 check 名（默认 `llm_prompt_injection`）。
        source: 来源标记 `builtin` / `skills`。
    """

    id: str
    category: str
    turns: list[dict]
    match: list[dict]
    owasp: str
    severity: str = "high"
    description: str = ""
    fix: str = ""
    check: str = "llm_prompt_injection"
    source: str = "builtin"

    def to_rule(self) -> dict[str, Any]:
        """归一化为引擎级 rule dict（`fire_attack` / `judge_response` / `run_probe` 通用）。"""
        return {
            "name": self.id,
            "type": "llm_vuln",
            "check": self.check,
            "owasp": self.owasp,
            "severity": self.severity,
            "description": self.description,
            "fix": self.fix,
            "turns": self.turns,
            "match": self.match,
        }


@dataclass
class ProbeResult:
    """单条探针的执行结果（含未命中，供测试集统计 ASR）。"""

    probe_id: str
    category: str
    owasp: str
    hit: bool
    evidence: str = ""
    confidence: float = 0.0
    error: str = ""
    finding: Any = None  # AIRiskFinding | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "probe_id": self.probe_id,
            "category": self.category,
            "owasp": self.owasp,
            "hit": self.hit,
            "confidence": self.confidence,
            "evidence": self.evidence[:300],
            "error": self.error,
        }


@dataclass
class ProbeSummary:
    """一次探针批次运行的汇总。"""

    total: int = 0
    hits: int = 0
    by_category: dict[str, dict[str, int]] = field(default_factory=dict)

    @property
    def asr(self) -> float:
        return self.hits / self.total if self.total else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "hits": self.hits,
            "asr": round(self.asr, 4),
            "by_category": self.by_category,
        }

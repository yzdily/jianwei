"""FastScanner 核心数据模型 —— ScanTarget / VulnFinding。

对应 xuanjian `core/fast_scanner/_models`，为本平台层 reinterpretation：
- ScanTarget：通用扫描目标（Web / API / LLM 应用 / Agent / RAG / Skill 包）
- VulnFinding：统一漏洞发现（平台层 L2-L5 共用 schema）
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ScanTarget:
    """通用扫描目标。

    extra 字段承载各目标类型的专属上下文：
      - extra["llm"]   = {mode, model, tools, chat_schema}  （llm_app/agent/rag）
      - extra["skill"] = {path, ingest_source}               （skill 包）
    """

    url: str = ""
    headers: dict = field(default_factory=dict)
    extra: dict = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    target_type: str = "web"
    strategy: str = "standard"

    @property
    def llm_meta(self) -> dict:
        return self.extra.get("llm", {}) or {}

    @property
    def skill_meta(self) -> dict:
        return self.extra.get("skill", {}) or {}


@dataclass
class VulnFinding:
    """统一漏洞发现。

    字段对齐 xuanjian VulnFinding + 鉴微 AI 风险扩展（file_path/line/safe_to_install）。
    """

    vuln_type: str
    severity: str
    url: str = ""
    method: str = "GET"
    detail: str = ""
    evidence: str = ""
    payload: str = ""
    fix_suggestion: str = ""
    evidence_quality: str = ""
    rule_tag: str = ""
    trace_id: str = ""
    confidence: float = 0.0
    owasp: str = ""
    # 静态/供应链扫描专用
    file_path: str = ""
    line: int = 0
    safe_to_install: bool = True

    def to_dict(self) -> dict:
        return {
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "url": self.url,
            "method": self.method,
            "detail": self.detail,
            "evidence": (self.evidence or "")[:500],
            "payload": (self.payload or "")[:200],
            "fix_suggestion": self.fix_suggestion,
            "evidence_quality": self.evidence_quality,
            "rule_tag": self.rule_tag,
            "trace_id": self.trace_id,
            "confidence": self.confidence,
            "owasp": self.owasp,
            "file_path": self.file_path,
            "line": self.line,
            "safe_to_install": self.safe_to_install,
        }

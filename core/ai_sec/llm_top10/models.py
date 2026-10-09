"""LLM 扫描目标与结果模型。"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class LLMScanTarget:
    """LLM 扫描目标 — 被测 LLM 应用端点。"""
    url: str
    headers: dict = field(default_factory=dict)
    model: str = "default"
    mode: str = "active"  # active / passive
    tools: list = field(default_factory=list)
    chat_schema: dict | None = None
    auth: dict | None = None

    @property
    def extra(self) -> dict:
        return {"llm": {
            "mode": self.mode,
            "model": self.model,
            "tools": self.tools,
            "chat_schema": self.chat_schema,
        }}


@dataclass
class LLMScanResult:
    """LLM 扫描结果。"""
    target_url: str
    findings: list = field(default_factory=list)
    total_attacks: int = 0
    successful_attacks: int = 0
    elapsed: float = 0.0
    rules_run: int = 0

    @property
    def asr(self) -> float:
        """Attack Success Rate。"""
        return self.successful_attacks / self.total_attacks if self.total_attacks > 0 else 0.0

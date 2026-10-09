"""sec_shield 护栏引擎 — 输入校验/策略引擎/输出过滤。"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

try:
    from core.log import get_logger
except Exception:
    import logging
    def get_logger(name): return logging.getLogger(name)

log = get_logger("ai_sec.sec_shield")


@dataclass
class ShieldResult:
    allowed: bool
    blocked_reason: str = ""
    filtered_content: str = ""
    matched_rules: list[str] = field(default_factory=list)


class SecShield:
    """可插拔护栏：输入校验 -> 策略引擎 -> 输出过滤。"""

    def __init__(self):
        self._input_validators: list[dict] = []
        self._output_filters: list[dict] = []
        self._policies: list[dict] = []

    def add_input_validator(self, name: str, patterns: list[str], action: str = "block"):
        self._input_validators.append({"name": name, "patterns": patterns, "action": action})

    def add_output_filter(self, name: str, patterns: list[str], replacement: str = "[REDACTED]"):
        self._output_filters.append({"name": name, "patterns": patterns, "replacement": replacement})

    def add_policy(self, name: str, rules: dict):
        self._policies.append({"name": name, "rules": rules})

    def validate_input(self, text: str) -> ShieldResult:
        """输入校验：检测注入/越狱/PII。"""
        matched = []
        for v in self._input_validators:
            for pattern in v["patterns"]:
                if re.search(pattern, text, re.IGNORECASE):
                    matched.append(v["name"])
                    if v["action"] == "block":
                        return ShieldResult(
                            allowed=False,
                            blocked_reason=f"blocked by {v['name']}",
                            matched_rules=matched,
                        )
        return ShieldResult(allowed=True, matched_rules=matched)

    def filter_output(self, text: str) -> ShieldResult:
        """输出过滤：脱敏 PII/密钥。"""
        filtered = text
        matched = []
        for f in self._output_filters:
            for pattern in f["patterns"]:
                if re.search(pattern, filtered, re.IGNORECASE):
                    matched.append(f["name"])
                    filtered = re.sub(pattern, f["replacement"], filtered, flags=re.IGNORECASE)
        return ShieldResult(allowed=True, filtered_content=filtered, matched_rules=matched)

    def process(self, input_text: str, output_text: str) -> tuple[ShieldResult, ShieldResult]:
        """自攻自防闭环入口：同时校验输入和过滤输出。"""
        return self.validate_input(input_text), self.filter_output(output_text)

    def load_default_policies(self):
        """加载默认策略：PII/越狱/密钥/敏感词。"""
        self.add_input_validator("prompt_injection", [
            r"忽略.*指令", r"ignore.*instructions", r"system.*prompt",
            r"你是一个.*助手", r"role.?play",
        ])
        self.add_input_validator("pii_query", [
            r"\b1[3-9]\d{9}\b", r"身份证", r"手机号",
        ])
        self.add_output_filter("api_keys", [
            r"sk-[A-Za-z0-9]{20,}", r"AKIA[0-9A-Z]{16}",
            r"api[_-]?key[=: ]+[A-Za-z0-9]{16,}",
        ])
        self.add_output_filter("secrets", [
            r"password[=: ]+\S+", r"secret[=: ]+\S+",
            r"token[=: ]+[A-Za-z0-9]{16,}",
        ])
        self.add_output_filter("internal_paths", [
            r"/etc/passwd", r"/etc/shadow", r"C:\\Windows\\System32",
        ])
        log.info("default policies loaded")

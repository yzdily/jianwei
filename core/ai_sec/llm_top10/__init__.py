"""L2 - OWASP LLM Top 10 漏洞扫描器。

对应 818 设计文档 §3.2 模块划分。
零侵入接入玄鉴 FastScanner：通过 _ChecksLLM mixin + rules/llm_vuln.yaml。
"""
from .scanner import LLMScanner
from .models import LLMScanTarget, LLMScanResult

__all__ = ["LLMScanner", "LLMScanTarget", "LLMScanResult"]

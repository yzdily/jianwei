"""L2 · Prompt 注入 / 越狱测试集（OWASP LLM01/LLM06/LLM07/LLM08）。

- 内置探针库 `library/`（direct / indirect / jailbreak / multimodal）
- 注册表 `ProbeRegistry`（内置 + skills_my/redteam 收编）
- 运行器 `ProbeRunner`（复用引擎级 `fire_attack`/`judge_response`，不重写检测逻辑）

用法::

    from core.ai_sec.prompt_injection import ProbeRegistry, ProbeRunner

    reg = ProbeRegistry.load("redteam")          # 内置 + skills
    runner = ProbeRunner(reg)
    results = await runner.run(target)            # 逐条 ProbeResult
    summary = ProbeRunner.summarize(results)      # ASR / 分类计数
    findings = ProbeRunner.findings(results)      # AIRiskFinding 列表
"""
from __future__ import annotations

from core.ai_sec.prompt_injection.models import (
    CATEGORIES,
    Probe,
    ProbeResult,
    ProbeSummary,
)
from core.ai_sec.prompt_injection.registry import ProbeRegistry
from core.ai_sec.prompt_injection.runner import ProbeRunner, run_probes

__all__ = [
    "CATEGORIES",
    "Probe",
    "ProbeResult",
    "ProbeSummary",
    "ProbeRegistry",
    "ProbeRunner",
    "run_probes",
]

"""内置注入探针库（builtin）。

四类：direct / indirect / jailbreak / multimodal。
新增探针只需在对应模块追加 `Probe(...)`，运行器与统计自动纳入。
"""
from __future__ import annotations

from core.ai_sec.prompt_injection.library.direct import PROBES as DIRECT
from core.ai_sec.prompt_injection.library.indirect import PROBES as INDIRECT
from core.ai_sec.prompt_injection.library.jailbreak import PROBES as JAILBREAK
from core.ai_sec.prompt_injection.library.multimodal import PROBES as MULTIMODAL

BUILTIN_PROBES = [*DIRECT, *INDIRECT, *JAILBREAK, *MULTIMODAL]

__all__ = ["BUILTIN_PROBES", "DIRECT", "INDIRECT", "JAILBREAK", "MULTIMODAL"]

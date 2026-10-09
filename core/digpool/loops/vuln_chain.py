# VENDORED MIRROR — 玄鉴 XuanJian v2.0 core/loops/vuln_chain.py
#
# 本文件为上游引擎 v2.0 的逐字镜像，仅供鉴微开发/测试环境（未 pip 安装 xuanjian 时）
# 作为 LoopController 的本地后备实现。生产环境通过 core_link.get_loop_controller() 优先
# 使用真实 xuanjian 包，绝不修改本镜像逻辑。若上游发版，须同步更新本镜像。
#
# 来源：F:\xuanjian-main\core\loops\vuln_chain.py (F8 漏洞链持久化 + depth_chain 审计)
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ChainStep:
    step: str
    chain_id: str
    ts: float
    finding_id: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)


class VulnChainMemory:
    """漏洞链持久化（内存版，复用 scan_store 做落盘）。"""

    def __init__(self) -> None:
        self.chains: dict[str, list[ChainStep]] = {}

    def append(
        self, trigger: str, step: str, finding: dict[str, Any] | None = None,
    ) -> None:
        chain_id = f"{trigger}:{step}"
        chain_step = ChainStep(
            step=step,
            chain_id=chain_id,
            ts=time.time(),
            finding_id=(finding or {}).get("finding_id") or (finding or {}).get("id"),
            detail=finding or {},
        )
        self.chains.setdefault(trigger, []).append(chain_step)

    def get_depth(self, trigger: str) -> int:
        return len(self.chains.get(trigger, []))

    def get_chain(self, trigger: str) -> list[ChainStep]:
        return list(self.chains.get(trigger, []))

    def has_trigger(self, trigger: str) -> bool:
        return trigger in self.chains

    def all_triggers(self) -> list[str]:
        return list(self.chains.keys())


__all__ = ["VulnChainMemory", "ChainStep"]

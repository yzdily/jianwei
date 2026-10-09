# 鉴微 DigPool · 上游 LOOP 引擎的 vendored mirror
#
# 生产环境通过 core.digpool.core_link.get_loop_controller() 优先调用真实
# xuanjian.core.loops.loop_controller.LoopController；本包仅在 xuanjian 未安装时
# 作为开发/测试后备。逻辑与 v2.0 逐字一致，禁止功能性修改。
from .loop_controller import Finding, LoopController
from .vuln_chain import ChainStep, VulnChainMemory
from .gates import FRAMEWORK_TRIGGERS, gate_2_5_depth_check

__all__ = [
    "LoopController",
    "Finding",
    "VulnChainMemory",
    "ChainStep",
    "gate_2_5_depth_check",
    "FRAMEWORK_TRIGGERS",
]

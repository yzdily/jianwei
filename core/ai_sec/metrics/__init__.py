"""L4 - 评测度量层。

ASR / 拒答率 / 泄露率 / 护栏拦截率 / 回归基线。
- `MetricsCalculator`：聚合计算
- `MetricsHook`：把扫描产物接进度量（飞轮挂钩）
- `BaselineStore` / `compare`：Golden 基线回归对比
"""
from .baseline import BaselineStore, compare
from .calculator import MetricsCalculator, MetricSummary
from .hook import MetricsHook, metrics_for_findings, render_metrics_section

__all__ = [
    "MetricsCalculator",
    "MetricSummary",
    "MetricsHook",
    "metrics_for_findings",
    "render_metrics_section",
    "BaselineStore",
    "compare",
]

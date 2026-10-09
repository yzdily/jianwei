"""鉴微 FastScanner —— 平台层扫描引擎包。

导出 FastScanner / scan / ScanTarget / VulnFinding。
"""
from ._engine import FastScanner, scan
from ._models import ScanTarget, VulnFinding

__all__ = ["FastScanner", "scan", "ScanTarget", "VulnFinding"]

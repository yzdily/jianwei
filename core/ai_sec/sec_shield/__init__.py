"""L3 - 护栏引擎 sec_shield。

输入校验 -> 策略引擎 -> 输出过滤（可插拔）。
自攻自防闭环：同时作为 L2 评测的被测对象。
"""
from .engine import SecShield

__all__ = ["SecShield"]

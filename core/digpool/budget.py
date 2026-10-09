"""L4 细粒度 token 计量（BudgetMeter）——「计划预算」 vs 「实际消耗」的偏差闭环。

对齐《MVP_GAP_ANALYSIS.md》P1 待改项「治理-预算/验收：接真实 token 计数（细粒度）」：

- **计划预算**：Planner 按阶段估算（`plan.budget_tokens`）；
- **实际消耗**：按每次执行的真实产物（工具输出 / LOOP findings / 验证结果）做**无依赖近似计量**，
  不依赖任何第三方 tokenizer（离线可跑，且计量口径统一可审计）；
- **偏差**：`actual > planned` → 超预算（熔断标记），报告如实标注，演示更接近真实治理。

零依赖约束：仅用标准库（json/re），与 digpool 其余模块一致。
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Optional

# 近似口径（无 tokenizer 时的公开约定，见 estimate_tokens 文档）：
#   - 非 ASCII 字符按 1 token / 字符（中文、日文等表意字符近似）
#   - ASCII 文本按 4 字符 / token（国际通用近似）
_ASCII_PER_TOKEN = 4
_NON_ASCII_PER_TOKEN = 1
# 单条记录最小计费（结构性开销：字段名、分隔符、JSON 包装等）
_MIN_RECORD_TOKENS = 8


def estimate_tokens(payload: Any) -> int:
    """对任意可 JSON 序列化产物做无依赖 token 近似估算。

    Args:
        payload: 字符串 / dict / list / bytes / 标量；dict/list 递归展开，bytes 按 utf-8 解码。

    Returns:
        int: 估算 token 数（>= 0）。
    """
    if payload is None:
        return 0
    if isinstance(payload, bytes):
        try:
            payload = payload.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001 - 解码失败按字节量近似
            return max(_MIN_RECORD_TOKENS, len(payload) // _ASCII_PER_TOKEN)
    if isinstance(payload, str):
        return _count_text(payload)
    if isinstance(payload, (dict, list)):
        try:
            text = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
        except Exception:  # noqa: BLE001 - 任意对象兜底
            text = str(payload)
        return _count_text(text)
    return _count_text(str(payload))


def _count_text(text: str) -> int:
    """按字符类别加权估算 token 数。

    说明：中文等表意字符信息密度高、tokenizer 通常 1 字近 1 token；
    英文/代码等 ASCII 序列按 4 字符 1 token 近似（OpenAI BPE 常见口径）。
    纯近似、口径统一，用于治理计量而非计费。
    """
    ascii_chars = non_ascii = 0
    for ch in text:
        if ord(ch) < 128:
            ascii_chars += 1
        else:
            non_ascii += 1
    tokens = non_ascii * _NON_ASCII_PER_TOKEN + ascii_chars / _ASCII_PER_TOKEN
    return max(0, int(tokens + 0.5))


@dataclass
class BudgetMeter:
    """预算计量器：累计实际消耗，比较计划预算，输出可供报告/治理消费的汇总。"""

    planned: int = 0
    usages: list[dict] = field(default_factory=list)

    def record(self, label: str, payload: Any = None, *, tokens: Optional[int] = None) -> int:
        """记录一次实际消耗（按 label 分类，便于报告归因）。

        Args:
            label: 消耗归属（如 `subtask:t3` / `verify` / `report`）。
            payload: 参与计量的真实产物（工具输出 / findings / 结果 dict）。
            tokens: 显式指定消耗量；缺省用 `estimate_tokens(payload)`。

        Returns:
            int: 本次记录消耗的 token 数。
        """
        cost = _MIN_RECORD_TOKENS if tokens is None else int(tokens)
        if tokens is None and payload is not None:
            cost = max(_MIN_RECORD_TOKENS, estimate_tokens(payload))
        self.usages.append({
            "label": label,
            "tokens": cost,
            "ts": len(self.usages),  # 顺序号（避免依赖 time，保证可复现测试）
        })
        return cost

    @property
    def actual(self) -> int:
        return sum(u["tokens"] for u in self.usages)

    @property
    def remaining(self) -> int:
        return max(0, self.planned - self.actual)

    @property
    def over(self) -> bool:
        return self.planned > 0 and self.actual > self.planned

    def summary(self) -> dict:
        """输出统一汇总 dict（报告 / SSE / 结果 dict 直接消费）。"""
        return {
            "planned": self.planned,
            "actual": self.actual,
            "remaining": self.remaining,
            "over": self.over,
            "breakdown": list(self.usages),
        }

    def __repr__(self) -> str:  # pragma: no cover - 调试辅助
        return f"BudgetMeter(planned={self.planned}, actual={self.actual}, over={self.over})"


__all__ = ["estimate_tokens", "BudgetMeter"]
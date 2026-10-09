"""L4 · Golden 基线存储与回归对比（Δ 告警）。

指标计算落地后，"越测越准"需要一条回归基准：把某次评测冻结为基线，后续评测与之对比，
指标劣化超阈值即告警（防"加 AI 层后旧引擎检测退化"）。
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

__all__ = ["BaselineStore", "compare", "METRIC_KEYS"]

# 仓库默认基线文件
DEFAULT_PATH = Path(__file__).resolve().parents[3] / "tests" / "golden" / "metrics_baseline.json"

METRIC_KEYS = ("asr", "refusal_rate", "leak_rate", "shield_block_rate")

# 方向：护栏拦截率越高越好；其余（ASR/拒答率/泄露率）作为目标侧指标，越低（越被防住）越好
_HIGHER_IS_BETTER = {"shield_block_rate"}


def compare(current: Any, baseline: dict, *, tolerance: float = 0.05) -> dict:
    """对比当前指标与基线。

    Returns:
        {deltas, regressions, tolerance, ok}
        deltas: 各指标 Δ；regressions: 劣化超阈值的指标名；ok: 无劣化。
    """
    cur = current.to_dict() if hasattr(current, "to_dict") else dict(current)
    deltas: dict[str, float] = {}
    regressions: list[str] = []
    for m in METRIC_KEYS:
        if m not in baseline:
            continue
        delta = round(float(cur.get(m, 0.0)) - float(baseline.get(m, 0.0)), 4)
        deltas[m] = delta
        higher_better = m in _HIGHER_IS_BETTER
        worse = (delta < -tolerance) if higher_better else (delta > tolerance)
        if worse:
            regressions.append(m)
    return {"deltas": deltas, "regressions": regressions, "tolerance": tolerance, "ok": not regressions}


class BaselineStore:
    """JSON 文件基线库（默认 `tests/golden/metrics_baseline.json`）。"""

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else DEFAULT_PATH
        self._data: dict[str, dict] = {}
        if self.path.exists():
            try:
                self._data = json.loads(self.path.read_text(encoding="utf-8"))
            except Exception:
                self._data = {}

    def save(self, name: str, summary: Any) -> None:
        self._data[name] = summary.to_dict() if hasattr(summary, "to_dict") else dict(summary)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._data, ensure_ascii=False, indent=2), encoding="utf-8")

    def get(self, name: str) -> dict | None:
        return self._data.get(name)

    def names(self) -> list[str]:
        return sorted(self._data)

    def compare(self, name: str, summary: Any, *, tolerance: float = 0.05) -> dict:
        base = self.get(name)
        if base is None:
            return {"ok": True, "regressions": [], "deltas": {}, "baseline_missing": True}
        out = compare(summary, base, tolerance=tolerance)
        out["baseline_missing"] = False
        return out

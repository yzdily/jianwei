"""基准测试运行器 —— 把 LLMVault 标注靶场转化为鉴微的可量化指标（设计 §7）。

用法：
  from core.llm_security.benchmark import run_benchmark_from_file
  report = await run_benchmark_from_file("tests/golden/llmvault_benchmark.jsonl")

每个标注样本含：攻击序列 + 确定性判定 + 期望命中（ground truth）。
运行器以 mock 响应器回放标注响应，经 run_probe 判定，统计：
  检测率(Recall) / 误报率(FP) / 准确率 / 混淆矩阵。
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.log import get_logger
from core.llm_security._probe import run_probe

log = get_logger("llm_security.benchmark")


@dataclass
class BenchmarkReport:
    total: int = 0
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    per_class: dict = field(default_factory=dict)

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 1.0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 1.0

    @property
    def accuracy(self) -> float:
        correct = self.tp + self.tn
        return correct / self.total if self.total else 1.0

    def to_dict(self) -> dict:
        return {
            "total": self.total, "tp": self.tp, "fp": self.fp,
            "tn": self.tn, "fn": self.fn,
            "recall": round(self.recall, 4),
            "precision": round(self.precision, 4),
            "accuracy": round(self.accuracy, 4),
            "per_class": self.per_class,
        }


def _make_target() -> Any:
    return type("T", (), {"url": "mock://llmvault", "extra": {"llm": {"model": "default"}}})()


async def run_benchmark(samples: list[dict]) -> BenchmarkReport:
    """对标注样本逐条回放，统计检测指标。"""
    report = BenchmarkReport()
    target = _make_target()

    for s in samples:
        rule = {
            "name": s.get("experiment_id", "sample"),
            "owasp": s.get("owasp", ""),
            "check": s.get("expected_check", "llm_vuln"),
            "severity": s.get("severity", "high"),
            "description": s.get("description", ""),
            "turns": s.get("attack_turns", []),
            "match": s.get("match", []),
            "fix": "",
        }
        mock_response = s.get("mock_response", "")
        finding = await run_probe(target, rule, responder=lambda m, p: mock_response)
        hit = finding is not None
        expected = bool(s.get("expected_hit", False))

        cls = s.get("owasp", "unknown")
        report.per_class.setdefault(cls, {"tp": 0, "fp": 0, "tn": 0, "fn": 0})
        if hit and expected:
            report.tp += 1; report.per_class[cls]["tp"] += 1
        elif hit and not expected:
            report.fp += 1; report.per_class[cls]["fp"] += 1
        elif (not hit) and (not expected):
            report.tn += 1; report.per_class[cls]["tn"] += 1
        else:
            report.fn += 1; report.per_class[cls]["fn"] += 1
        report.total += 1

    log.info(f"benchmark: recall={report.recall:.2%} precision={report.precision:.2%} acc={report.accuracy:.2%}")
    return report


async def run_benchmark_from_file(path: str | Path) -> BenchmarkReport:
    """从 jsonl 标注文件加载并运行基准。"""
    samples = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                samples.append(json.loads(line))
    return await run_benchmark(samples)

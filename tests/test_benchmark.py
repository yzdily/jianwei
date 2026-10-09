"""基准测试（设计 §7）：用 LLMVault 标注样本验证检测逻辑。"""
import pytest
from pathlib import Path

from core.llm_security.benchmark import run_benchmark_from_file

GOLDEN = Path(__file__).parent / "golden" / "llmvault_benchmark.jsonl"


@pytest.mark.asyncio
async def test_benchmark_recall_on_labeled():
    report = await run_benchmark_from_file(GOLDEN)
    assert report.total == 32
    # 标注响应均按 ground truth 构造，期望完美检测
    assert report.recall == 1.0
    assert report.precision == 1.0
    assert report.fn == 0
    assert report.fp == 0

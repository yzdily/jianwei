"""Live LLMVault 实测集成测试（设计 §7 / benchmark_plan §2）。

默认**跳过**：需要本地/授权靶场。满足以下任一条件才运行：
  - 环境变量 LLMVAULT_URL 指向可达的靶场 chat 端点；或
  - 本机 docker 可用且已拉起 LLMVault 靶场。

运行方式：
  LLMVAULT_URL=http://127.0.0.1:5000 pytest tests/test_live_benchmark.py -s

该测试把 tests/golden/llmvault_benchmark.jsonl 真实打到靶场，回填真实召回，
用于替代 benchmark_report.md 中的 golden 基线口径。
"""
from __future__ import annotations

import os
import shutil
import socket
from pathlib import Path

import pytest

GOLDEN = Path(__file__).parent / "golden" / "llmvault_benchmark.jsonl"


def _target_reachable(url: str, timeout: float = 1.5) -> bool:
    try:
        from urllib.parse import urlparse
        p = urlparse(url)
        host = p.hostname or "127.0.0.1"
        port = p.port or 80
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


_LLMVAULT_URL = os.getenv("LLMVAULT_URL", "")
_DOCKER = shutil.which("docker") is not None
_RUN_LIVE = bool(_LLMVAULT_URL) and _target_reachable(_LLMVAULT_URL)

pytestmark = pytest.mark.skipif(
    not _RUN_LIVE,
    reason="未检测到可达的 LLMVault 靶场（设 LLMVAULT_URL 并确保可达后启用）",
)


@pytest.mark.asyncio
async def test_live_benchmark_real_target():
    from core.llm_security.live_benchmark import load_samples, run_live_benchmark

    samples = load_samples(GOLDEN)
    report = await run_live_benchmark(_LLMVAULT_URL, samples)
    d = report.to_dict()
    # 真实靶场不保证 100%，但应至少能完成全部样本
    assert d["total"] == len(samples)
    print(f"\n[LIVE] recall={d['recall']:.2%} precision={d['precision']:.2%} "
          f"tp={d['tp']} fp={d['fp']} tn={d['tn']} fn={d['fn']}")

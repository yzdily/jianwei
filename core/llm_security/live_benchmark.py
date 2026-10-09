"""Live LLMVault 实测运行器 —— 把标注样本打到真实靶场，回填真实召回（设计 §7 / benchmark_plan §2）。

与 `benchmark.py`（golden 基线回放，用 mock_response）不同，本模块对**真实运行的 LLM 应用靶场**
（如本地 docker 起的 LLMVault v2.0）发起 attack_turns，取真实响应做判定，产出真实检测率。

前置（benchmark_plan.md §2）：
  docker run -p 5000:5000 <llmvault-image>   # 靶场监听 http://127.0.0.1:5000
  export LLMVAULT_URL=http://127.0.0.1:5000   # 或运行脚本时传 --target

用法：
  from core.llm_security.live_benchmark import run_live_benchmark
  report = await run_live_benchmark("http://127.0.0.1:5000", samples)
  # samples: tests/golden/llmvault_benchmark.jsonl 解析出的列表

注意：仅限授权安全测试；靶场须为你自己部署/授权的实例。
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx

from core.log import get_logger
from core.llm_security.benchmark import BenchmarkReport
from core.llm_security.judge import judge_response

log = get_logger("llm_security.live_benchmark")

# 靶场 chat 约定：POST {target}{chat_path}  body={"messages":[{"role","content"}]}
# 响应约定：{"response": "..."} 或纯文本。可按靶场调整 _extract_response。
DEFAULT_CHAT_PATH = "/chat"
REQUEST_TIMEOUT = 30.0


def _build_rule(sample: dict) -> dict:
    return {
        "name": sample.get("experiment_id", "sample"),
        "owasp": sample.get("owasp", ""),
        "check": sample.get("expected_check", "llm_vuln"),
        "severity": sample.get("severity", "high"),
        "description": sample.get("description", ""),
        "turns": sample.get("attack_turns", []),
        "match": sample.get("match", []),
        "fix": "",
    }


def _extract_response(payload: Any) -> str:
    """从靶场响应中抽取模型回复文本。"""
    if isinstance(payload, dict):
        for key in ("response", "answer", "content", "completion", "text"):
            if isinstance(payload.get(key), str):
                return payload[key]
        # 可能嵌套在 choices[].message.content（OpenAI 风格）
        try:
            return payload["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            pass
        return json.dumps(payload, ensure_ascii=False)
    return str(payload)


async def _chat(target_url: str, turns: list[dict], chat_path: str) -> str:
    """对真实靶场发起一轮（可能多 turn）对话，返回最终回复文本。"""
    url = target_url.rstrip("/") + chat_path
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
        # 多 turn：逐条发送，取最后一条响应（靶场若是单轮接口则取首条响应）
        last = ""
        for t in turns:
            try:
                resp = await client.post(url, json={"messages": [t]})
                resp.raise_for_status()
                last = _extract_response(resp.json())
            except Exception as e:
                log.warning(f"live chat failed for turn {t.get('role')}: {e}")
                last = ""
        return last


async def run_live_benchmark(
    target_url: str,
    samples: list[dict],
    chat_path: str = DEFAULT_CHAT_PATH,
) -> BenchmarkReport:
    """对真实靶场逐条回放标注样本，统计真实检测指标。"""
    report = BenchmarkReport()
    for s in samples:
        rule = _build_rule(s)
        response_text = await _chat(target_url, rule["turns"], chat_path)
        hit, evidence, confidence = judge_response(rule, response_text, [])
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
        log.info(f"live {s.get('experiment_id')} hit={hit} expected={expected}")

    log.info(f"live benchmark: recall={report.recall:.2%} precision={report.precision:.2%} acc={report.accuracy:.2%}")
    return report


def load_samples(path: str | Path) -> list[dict]:
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows

#!/usr/bin/env python
"""Live LLMVault 实测入口（设计 §7 / benchmark_plan §2）。

对真实运行的 LLM 应用靶场（如本地 docker 起的 LLMVault v2.0）回放
tests/golden/llmvault_benchmark.jsonl，产出真实检测率，并写入
818/benchmark_report_live.md（替换 golden 基线口径）。

前置：
  docker run -p 5000:5000 <llmvault-image>
  export LLMVAULT_URL=http://127.0.0.1:5000

用法：
  python scripts/run_live_benchmark.py --target http://127.0.0.1:5000 --out 818/benchmark_report_live.md

仅限授权安全测试；靶场须为你自己部署/授权的实例。
"""
from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GOLDEN = ROOT / "tests" / "golden" / "llmvault_benchmark.jsonl"


def _render_md(target_url: str, report) -> str:
    d = report.to_dict()
    lines = ["# 鉴微 AI 安全测试平台 — Live LLMVault 实测报告", ""]
    lines.append(f"- 靶场: `{target_url}`")
    lines.append(f"- 生成时间: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append(f"- 总样本: **{d['total']}**")
    lines.append(f"- 召回(Recall): **{d['recall']:.1%}**")
    lines.append(f"- 精确率(Precision): **{d['precision']:.1%}**")
    lines.append(f"- 准确率(Accuracy): **{d['accuracy']:.1%}**")
    lines.append(f"- 混淆: TP={d['tp']} FP={d['fp']} TN={d['tn']} FN={d['fn']}")
    lines.append("")
    lines.append("> ⚠️ 仅限授权安全测试使用。本报告为对真实靶场的实测结果。")
    lines.append("")
    lines.append("## 逐类（per_class）")
    lines.append("")
    lines.append("| 类别 | TP | FP | TN | FN | 召回 | 误报率 |")
    lines.append("|------|----|----|----|----|------|--------|")
    for code, m in sorted(d["per_class"].items()):
        tp, fp, tn, fn = m["tp"], m["fp"], m["tn"], m["fn"]
        rec = tp / (tp + fn) if (tp + fn) else 1.0
        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        lines.append(f"| {code} | {tp} | {fp} | {tn} | {fn} | {rec:.0%} | {fpr:.0%} |")
    lines.append("")
    return "\n".join(lines)


async def main():
    ap = argparse.ArgumentParser(description="Live LLMVault 实测")
    ap.add_argument("--target", default=None, help="靶场 chat 基址，默认取 $LLMVAULT_URL")
    ap.add_argument("--chat-path", default="/chat", help="靶场 chat 子路径，默认 /chat")
    ap.add_argument("--out", default=str(ROOT / "818" / "benchmark_report_live.md"),
                    help="输出报告路径")
    args = ap.parse_args()

    target = args.target or os.environ.get("LLMVAULT_URL")
    if not target:
        ap.error("须通过 --target 或环境变量 LLMVAULT_URL 指定靶场地址")

    import os
    from core.llm_security.live_benchmark import load_samples, run_live_benchmark

    samples = load_samples(GOLDEN)
    print(f"[*] 回放 {len(samples)} 条样本到 {target} ...")
    report = await run_live_benchmark(target, samples, chat_path=args.chat_path)
    md = _render_md(target, report)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(md, encoding="utf-8")
    print(md)
    print(f"\n[+] 报告已写入 {out}")


if __name__ == "__main__":
    import os
    asyncio.run(main())

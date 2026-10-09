"""鉴微 CLI —— 命令行入口（设计 Skill §4.3 借鉴 SkillSpector CLI）。

用法：
  python -m core.cli scan-skill ./my-skill/ --strategy redteam --format sarif
  python -m core.cli scan https://llm.example.com/v1/chat --target-type llm_app --strategy standard

也可用 start.py 转发：
  python start.py scan-skill ./my-skill/
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys

from core.log import get_logger

log = get_logger("cli")


def _cmd_scan_skill(args) -> int:
    from core.llm_security.skill_scan import scan_package

    result = scan_package(args.path, strategy=args.strategy, use_llm=args.strategy == "redteam")
    if args.format == "sarif":
        out = result.sarif()
    else:
        out = result.to_dict()
    text = json.dumps(out, ensure_ascii=False, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"[OK] 结果已写入 {args.output}")
    else:
        print(text)
    return result.exit_code


def _cmd_scan(args) -> int:
    from core.fast_scanner import FastScanner, ScanTarget

    target = ScanTarget(url=args.target, target_type=args.target_type, extra=args.extra or {})
    scanner = FastScanner()
    findings = scanner.scan_target_sync(target, strategy=args.strategy, target_type=args.target_type)
    out = {
        "target_type": args.target_type,
        "strategy": args.strategy,
        "enabled_rules": scanner._scan_config.enabled_rules,
        "findings_count": len(findings),
        "findings": [f.to_dict() for f in findings],
    }
    text = json.dumps(out, ensure_ascii=False, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"[OK] 结果已写入 {args.output}")
    else:
        print(text)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="jianwei", description="鉴微 JianWei AI 安全测试平台 CLI")
    sub = p.add_subparsers(dest="command")

    sp = sub.add_parser("scan-skill", help="静态扫描技能包 / MCP server 包")
    sp.add_argument("path", help="本地目录 / zip / 单文件 SKILL.md / URL / git URL")
    sp.add_argument("--strategy", default="standard",
                    choices=["passive", "standard", "redteam", "compliance"])
    sp.add_argument("--format", default="json", choices=["json", "sarif"])
    sp.add_argument("--output", default="", help="结果写出文件路径")
    sp.set_defaults(func=_cmd_scan_skill)

    sc = sub.add_parser("scan", help="双轴扫描目标（Web/API/LLM/Agent/RAG）")
    sc.add_argument("target", help="目标 URL（skill 类型可省略）")
    sc.add_argument("--target-type", default="web",
                    choices=["web", "api", "llm_app", "agent", "rag", "skill"])
    sc.add_argument("--strategy", default="standard",
                    choices=["passive", "standard", "redteam", "compliance"])
    sc.add_argument("--extra", type=json.loads, default=None, help="额外上下文 JSON")
    sc.add_argument("--output", default="", help="结果写出文件路径")
    sc.set_defaults(func=_cmd_scan)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

"""M4 · Reporter —— 把闭环结果渲染为可交付报告并落盘。

对齐《鉴微优化方案 §5》M4 / TechPlan「REPORT 输出覆盖矩阵 + 漏洞详情 + PoC」：
- 覆盖矩阵（阶段 × 子任务 × 状态）
- 漏洞详情（仅 confirmed 进入；suspect/rejected 单列，体现双重去误报）
- 执行摘要（trigger / depth_chain / termination）
- 评测度量（可选，复用 L4 MetricsHook 段落）
- 项目记忆（记忆键 + recall，体现「越测越准」）

零依赖：纯字符串拼装；不导入任何第三方库。
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Iterable, Optional

from core.digpool.agents.planner import Plan
from core.digpool.agents.validator import VERDICT_CONFIRMED, VERDICT_REJECTED, VERDICT_SUSPECT, ValidationResult


def _cell(v: Any) -> str:
    return str("" if v is None else v).replace("|", "\\|").replace("\n", " ")


class Reporter:
    """报告渲染器（可注入 metrics 段落渲染函数）。"""

    def __init__(self, metrics_renderer: Any = None):
        self._metrics_renderer = metrics_renderer or _default_metrics_renderer

    def build(
        self,
        *,
        goal: str,
        target: Optional[str] = None,
        session_id: Optional[str] = None,
        run_id: Optional[str] = None,
        plan: Optional[Plan] = None,
        executions: Optional[list[dict]] = None,
        validation: Optional[list[ValidationResult]] = None,
        metrics: Any = None,
        memory_key: Optional[str] = None,
        memory_recall: Optional[dict] = None,
        budget: Optional[dict] = None,
        extra: Optional[dict] = None,
    ) -> str:
        execution_rows = {e.get("subtask"): e for e in (executions or []) if isinstance(e, dict)}
        lines: list[str] = []
        lines.append("# 鉴微 DigPool 安全测试报告")
        lines.append("")
        lines.append(f"- **目标**：{target or '(未指定)'}")
        lines.append(f"- **目标意图**：{goal}")
        lines.append(f"- **会话**：{session_id or '-'}　**运行**：{run_id or '-'}")
        lines.append(f"- **生成时间**：{time.strftime('%Y-%m-%d %H:%M:%S')}")
        if plan is not None:
            lines.append(f"- **预算估算**：{plan.budget_tokens} tokens")
        if budget is not None and isinstance(budget, dict):
            status = "超预算（熔断）" if budget.get("over") else "预算内"
            lines.append(
                f"- **预算实测**：实际 {budget.get('actual', 0)} / 计划 "
                f"{budget.get('planned', 0)} tokens（{status}）"
            )
        lines.append("")

        # 1. 执行摘要
        lines.append("## 1. 执行摘要")
        lines.append("")
        if executions:
            lines.append("| 子任务 | 动作 | 结果 |")
            lines.append("|---|---|---|")
            for e in executions:
                action = e.get("action") or "-"
                detail = e.get("trigger") or e.get("tool") or "-"
                if e.get("action") == "loop":
                    result = f"{detail}｜depth={e.get('depth_chain')}｜termination={e.get('termination')}"
                else:
                    result = f"{detail}｜{e.get('summary') or ('ok' if e.get('ok') else 'failed')}"
                lines.append(f"| {_cell(e.get('subtask'))} | {_cell(action)} | {_cell(result)} |")
        else:
            lines.append("_（无执行记录）_")
        lines.append("")

        # 2. 覆盖矩阵
        lines.append("## 2. 覆盖矩阵")
        lines.append("")
        if plan is not None and plan.subtasks:
            lines.append("| 阶段 | 子任务 | 说明 | 状态 |")
            lines.append("|---|---|---|---|")
            for st in plan.subtasks:
                ex = execution_rows.get(st.id)
                if st.phase in ("RECON", "SCOPE", "VERIFY", "REPORT"):
                    status = "done"
                elif ex is not None:
                    status = "done" if (ex.get("ok", True) and not ex.get("blocked_by_governance")) else "blocked"
                else:
                    status = "skipped"
                lines.append(
                    f"| {_cell(st.phase)} | {_cell(st.id)} | {_cell(st.description)} | {_cell(status)} |"
                )
        else:
            lines.append("_（无计划）_")
        lines.append("")

        # 3. 漏洞详情（仅已确认）
        results = list(validation or [])
        confirmed = [r for r in results if r.verdict == VERDICT_CONFIRMED]
        suspect = [r for r in results if r.verdict == VERDICT_SUSPECT]
        rejected = [r for r in results if r.verdict == VERDICT_REJECTED]

        lines.append("## 3. 漏洞详情（已验证）")
        lines.append("")
        lines.append(f"共 **{len(confirmed)}** 条确定性漏洞（经双重去误报）。")
        lines.append("")
        if confirmed:
            lines.append("| 严重级 | 类型 | 位置 | 置信度 | 发现 ID |")
            lines.append("|---|---|---|---|---|")
            for r in confirmed:
                d = r.to_dict()
                lines.append(
                    f"| {_cell(d['severity'])} | {_cell(d['vuln_type'])} | {_cell(d['location'])} "
                    f"| {_cell(d['confidence'])} | {_cell(d['id'])} |"
                )
        else:
            lines.append("_（无已确认漏洞）_")
        lines.append("")

        # 4. 疑似/去误报
        lines.append("## 4. 疑似与去误报")
        lines.append("")
        lines.append(f"- 疑似（证据不足，待人工复核）：**{len(suspect)}** 条")
        lines.append(f"- 被拒（无位置/重复）：**{len(rejected)}** 条")
        lines.append("")
        for group, name in ((suspect, "疑似"), (rejected, "被拒")):
            if not group:
                continue
            lines.append(f"### 4.{1 if name == '疑似' else 2} {name}")
            lines.append("")
            lines.append("| 类型 | 位置 | 原因 |")
            lines.append("|---|---|---|")
            for r in group:
                d = r.to_dict()
                lines.append(f"| {_cell(d['vuln_type'])} | {_cell(d['location'])} | {_cell('；'.join(d['reasons']))} |")
            lines.append("")

        # 5. 预算实测（L4 细粒度 token 计量，可选）
        if budget is not None and isinstance(budget, dict):
            lines.append("## 6. 预算实测（L4 计量）")
            lines.append("")
            lines.append(f"- 计划预算：**{budget.get('planned', 0)}** tokens")
            lines.append(f"- 实际消耗：**{budget.get('actual', 0)}** tokens")
            lines.append(f"- 剩余配额：{budget.get('remaining', 0)} tokens")
            status = "❌ 已超预算（熔断标记）" if budget.get("over") else "✅ 预算内"
            lines.append(f"- 状态：{status}")
            lines.append("- 计量口径：无依赖近似（非 ASCII 1 字 ≈ 1 token；ASCII 4 字符 ≈ 1 token）")
            lines.append("")
            breakdown = [u for u in (budget.get("breakdown") or []) if isinstance(u, dict)]
            if breakdown:
                lines.append("| 消耗归属 | 消耗（tokens） |")
                lines.append("|---|---|")
                for u in breakdown:
                    lines.append(f"| {_cell(u.get('label'))} | {_cell(u.get('tokens'))} |")
                lines.append("")

        # 6. 评测度量
        if metrics is not None:
            try:
                lines.append(self._metrics_renderer(metrics).rstrip())
                lines.append("")
            except Exception:  # noqa: BLE001 - 度量渲染失败不影响报告
                pass

        # 6. 项目记忆
        lines.append("## 5. 项目记忆")
        lines.append("")
        lines.append(f"- 记忆键：`{memory_key or '-'}`")
        if memory_recall:
            lines.append(f"- 历史运行次数：{memory_recall.get('run_count', 0)}（本次运行前）")
            known = memory_recall.get("known_vuln_types") or []
            if known:
                lines.append(f"- 已知漏洞类型：{', '.join(known)}")
            if memory_recall.get("last_termination"):
                lines.append(f"- 上次终止条件：{memory_recall['last_termination']}")
        lines.append("")

        if extra:
            lines.append("## 附：附加信息")
            lines.append("")
            for k, v in extra.items():
                lines.append(f"- {k}：{v}")
            lines.append("")

        return "\n".join(lines)

    def save(self, text: str, path: str | Path) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        return p


def _default_metrics_renderer(metrics: Any) -> str:
    from core.ai_sec.metrics.hook import render_metrics_section

    return render_metrics_section(metrics)


__all__ = ["Reporter"]

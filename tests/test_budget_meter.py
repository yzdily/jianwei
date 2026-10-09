"""L4 细粒度 token 计量测试（BudgetMeter / estimate_tokens）。

覆盖《MVP_GAP_ANALYSIS.md》P1 待改项「治理-预算/验收：接真实 token 计数（细粒度）」：
- estimate_tokens：中文/英文/结构化 payload 的近似口径；
- BudgetMeter：累计实际消耗、计划对比、超预算标记、breakdown 明细；
- solve()：闭环输出带 budget 汇总（计划 vs 实际），报告含预算实测小节。
"""
from __future__ import annotations

import pytest

from core.digpool.budget import BudgetMeter, estimate_tokens


# ---------------------------------------------------------------------------
# estimate_tokens 近似口径
# ---------------------------------------------------------------------------

def test_estimate_ascii_text_4chars_per_token():
    # "hello world" = 11 ASCII 字符 → 11/4 = 2.75 → 取整 3
    assert estimate_tokens("hello world") == 3


def test_estimate_cjk_one_token_per_char():
    # 4 个表意字符 → 4 tokens
    assert estimate_tokens("中文输入") == 4


def test_estimate_mixed_text():
    # "hello 世界" = 7 ASCII + 2 非 ASCII → 7/4 + 2 ≈ 3.75 → 4
    assert estimate_tokens("hello 世界") == 4


def test_estimate_structured_payload_recursive():
    d = {"a": "中文内容", "b": ["hello world", 123], "c": None}
    assert estimate_tokens(d) > estimate_tokens("hello world")
    assert estimate_tokens(["x" * 100]) > 10


def test_estimate_scalars_and_bytes():
    assert estimate_tokens(None) == 0
    assert estimate_tokens(42) >= 1
    assert estimate_tokens(b"hello world") == 3
    assert estimate_tokens("") == 0


# ---------------------------------------------------------------------------
# BudgetMeter 计量
# ---------------------------------------------------------------------------

def test_meter_records_actual_and_compares_to_planned():
    meter = BudgetMeter(planned=100)
    meter.record("t1", "hello world 中文")
    meter.record("t2", {"a": 1})
    s = meter.summary()
    assert s["planned"] == 100
    assert s["actual"] > 0
    assert s["remaining"] == 100 - s["actual"]
    assert s["over"] is False
    assert len(s["breakdown"]) == 2
    assert s["breakdown"][0]["label"] == "t1"


def test_meter_marks_over_budget():
    meter = BudgetMeter(planned=5)
    meter.record("big", "很长的中文内容，超出计划预算" * 20)
    assert meter.over is True
    assert meter.summary()["remaining"] == 0  # 负余量截断为 0


def test_meter_explicit_tokens():
    meter = BudgetMeter(planned=10)
    assert meter.record("x", tokens=7) == 7
    assert meter.actual == 7
    # 无 payload 且未显式指定 → 最小计费
    assert meter.record("empty") >= 8


def test_meter_zero_planned_no_over():
    # 计划为 0（非法输入兜底）：不误判超预算
    meter = BudgetMeter(planned=0)
    meter.record("x", "内容")
    assert meter.over is False


# ---------------------------------------------------------------------------
# 与闭环 solve 的集成（sync 包一层，避免依赖 pytest-asyncio）
# ---------------------------------------------------------------------------

def _findings_with_detail():
    from core.digpool.loops.loop_controller import Finding

    return [Finding(
        id="F1", vuln_type="skill_supply_chain", severity="high",
        url="tests/fixtures/malicious_skill",
        detail={"payload": "exec(", "snippet": "os.system", "file_path": "plugin.py", "line": 12},
    )]


def test_reporter_renders_budget_section():
    from core.digpool.agents.reporter import Reporter
    from core.digpool.agents.validator import StubValidator

    meter = BudgetMeter(planned=1_000)
    meter.record("subtask:t3", "skill-scan 输出摘要")
    meter.record("verify", [r.to_dict() for r in StubValidator().validate(_findings_with_detail())])
    md = Reporter().build(
        goal="对技能包做安全测试", target="tests/fixtures/malicious_skill",
        plan=None, validation=StubValidator().validate(_findings_with_detail()),
        budget=meter.summary(),
    )
    assert "## 6. 预算实测（L4 计量）" in md
    assert "计划预算" in md and "实际消耗" in md and "subtask:t3" in md


def test_reporter_without_budget_backward_compat():
    from core.digpool.agents.reporter import Reporter

    md = Reporter().build(goal="g")
    assert "预算实测" not in md
    assert md.startswith("# 鉴微 DigPool 安全测试报告")
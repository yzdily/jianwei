"""L4 · 度量飞轮（hook + baseline）测试。"""
from __future__ import annotations

from core.ai_sec.metrics import (
    BaselineStore,
    MetricsHook,
    compare,
    metrics_for_findings,
    render_metrics_section,
)
from core.ai_sec.models import AIRiskFinding


def _f(owasp="LLM01", sev="high"):
    return AIRiskFinding(owasp=owasp, vuln_type="t", severity=sev, url="u", detail="d")


class TestMetricsForFindings:
    def test_asr_and_leak(self):
        findings = [_f("LLM01"), _f("LLM02"), _f("LLM06")]
        s = metrics_for_findings(findings, total=6)
        assert s.total_attacks == 6
        assert s.successful_attacks == 3
        assert s.asr == 0.5
        assert s.leaks == 1  # 仅 LLM02 计入泄露


class TestMetricsHook:
    def test_record_accumulates(self):
        hook = MetricsHook()
        hook.record(findings=[_f("LLM01"), _f("LLM02")], total=4)
        hook.record(findings=[_f("LLM07")], total=4)
        s = hook.summary()
        assert s.total_attacks == 8
        assert s.successful_attacks == 3
        assert s.asr == 3 / 8
        assert hook.to_dict()["summary"]["asr"] == round(3 / 8, 4)

    def test_record_from_scan_result(self):
        class _Res:
            findings = [_f("LLM01")]
            total_attacks = 2

        s = MetricsHook().record(_Res())
        assert s.total_attacks == 2 and s.successful_attacks == 1

    def test_shield_block_rate(self):
        s = MetricsHook().record(findings=[], total=5, shield_total=5, shield_blocked=4)
        assert s.shield_block_rate == 0.8

    def test_render_section(self):
        md = render_metrics_section(metrics_for_findings([_f()], total=2))
        assert "攻击成功率" in md and "护栏拦截率" in md


class TestBaseline:
    def test_save_get_compare(self, tmp_path):
        store = BaselineStore(tmp_path / "base.json")
        base = metrics_for_findings([_f("LLM01")], total=4)  # asr 0.25
        store.save("golden", base)
        assert store.get("golden")["asr"] == 0.25
        assert store.names() == ["golden"]

        # 当前 ASR 升高（目标侧"更危险"）→ 视为回归（越差）
        cur = metrics_for_findings([_f("LLM01"), _f("LLM02")], total=4)  # asr 0.5
        out = store.compare("golden", cur, tolerance=0.05)
        assert out["baseline_missing"] is False
        assert "asr" in out["regressions"]
        assert out["ok"] is False

    def test_compare_missing_baseline(self, tmp_path):
        store = BaselineStore(tmp_path / "none.json")
        out = store.compare("nope", metrics_for_findings([_f()], total=1))
        assert out["baseline_missing"] is True and out["ok"] is True

    def test_compare_direction_shield_higher_better(self):
        base = {"shield_block_rate": 0.8}
        cur = {"shield_block_rate": 0.5}
        out = compare(cur, base, tolerance=0.05)
        assert "shield_block_rate" in out["regressions"]

    def test_no_regression_within_tolerance(self):
        base = {"asr": 0.5}
        cur = {"asr": 0.52}
        assert compare(cur, base, tolerance=0.05)["ok"] is True

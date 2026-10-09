"""双轴扫描策略测试（MASTER_PLAN §12 / Skill §3.1）。"""
import pytest
from core.scan_strategies import (
    get_scan_strategy, TargetType, TestStrategy, ScanConfig,
)


class TestDualAxis:
    def test_combination_count(self):
        """5×4 + skill 4 = 24 组合均可产出规则。"""
        n = 0
        for tt in TargetType:
            for st in TestStrategy:
                c = get_scan_strategy(tt, st)
                assert isinstance(c, ScanConfig)
                assert c.enabled_rules
                n += 1
        assert n == 24

    def test_llm_types_enable_llm_vuln(self):
        for tt in (TargetType.LLM_APP, TargetType.AGENT, TargetType.RAG):
            c = get_scan_strategy(tt, TestStrategy.STANDARD)
            assert "llm_vuln" in c.enabled_rules

    def test_web_api_not_enable_llm_vuln(self):
        for tt in (TargetType.WEB, TargetType.API):
            c = get_scan_strategy(tt, TestStrategy.STANDARD)
            assert "llm_vuln" not in c.enabled_rules

    def test_skill_only_skill_scan(self):
        for st in TestStrategy:
            c = get_scan_strategy(TargetType.SKILL, st)
            assert c.enabled_rules == ["skill_scan"]

    def test_passive_only_asset_discovery(self):
        for tt in (TargetType.WEB, TargetType.API, TargetType.LLM_APP, TargetType.AGENT, TargetType.RAG):
            c = get_scan_strategy(tt, TestStrategy.PASSIVE)
            assert c.enabled_rules == ["asset_discovery"]
        # skill 类型 passive 仍走 skill_scan（策略语义不同）
        c = get_scan_strategy(TargetType.SKILL, TestStrategy.PASSIVE)
        assert c.enabled_rules == ["skill_scan"]

    def test_string_inputs_accepted(self):
        c = get_scan_strategy("llm_app", "redteam")
        assert "llm_vuln" in c.enabled_rules
        assert c.strategy == TestStrategy.REDTEAM

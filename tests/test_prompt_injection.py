"""L2 · Prompt 注入测试集测试（纯离线，不依赖 httpx / 网络）。

覆盖：内置库完备性、skills 收编、Probe 归一化、运行器命中/未命中、汇总与 findings。
"""
from __future__ import annotations

from core.ai_sec.prompt_injection import (
    Probe,
    ProbeRegistry,
    ProbeRunner,
    run_probes,
)
from core.ai_sec.llm_top10.models import LLMScanTarget
from core.llm_security._probe import run_probe

TARGET = LLMScanTarget(url="http://test.local/v1/chat")


def _probe(pid: str) -> Probe:
    return next(p for p in ProbeRegistry.load_builtin().all() if p.id == pid)


# ── 注册表 ──────────────────────────────────────────────────────────

class TestRegistry:
    def test_builtin_count_and_categories(self):
        reg = ProbeRegistry.load_builtin()
        assert len(reg) >= 20, f"内置探针应 ≥20，实为 {len(reg)}"
        cats = reg.categories()
        for c in ("direct", "indirect", "jailbreak", "multimodal"):
            assert cats.get(c, 0) >= 1, f"缺类别 {c}"

    def test_all_probes_have_required_fields(self):
        for p in ProbeRegistry.load_builtin():
            assert p.id and p.category in ("direct", "indirect", "jailbreak", "multimodal")
            assert p.turns and p.match and p.owasp
            # 归一化后必须能被引擎判定器消费
            rule = p.to_rule()
            assert rule["turns"] and rule["match"] and rule["owasp"]

    def test_ids_unique(self):
        ids = [p.id for p in ProbeRegistry.load_builtin()]
        assert len(ids) == len(set(ids))

    def test_by_owasp(self):
        reg = ProbeRegistry.load_builtin()
        assert len(reg.by_owasp("LLM01")) >= 1
        assert len(reg.by_owasp("LLM07")) >= 1

    def test_load_from_skills_ingests_legacy_probes(self):
        reg = ProbeRegistry.load_builtin()
        before = len(reg)
        added = reg.load_from_skills()
        assert added >= 3, "应至少收编 skills_my/redteam 的 3 类探针"
        assert len(reg) == before + added
        assert any(p.source == "skills" for p in reg.all())

    def test_load_standard_is_builtin_only(self):
        reg = ProbeRegistry.load("standard")
        assert all(p.source == "builtin" for p in reg.all())

    def test_load_redteam_includes_skills(self):
        reg = ProbeRegistry.load("redteam")
        assert any(p.source == "skills" for p in reg.all())


# ── Probe 归一化 ────────────────────────────────────────────────────

class TestProbeModel:
    def test_to_rule_shape(self):
        p = Probe(
            id="x-1", category="direct",
            turns=[{"role": "user", "content": "hi"}],
            match=[{"pattern": "secret", "in": "response", "flags": "IGNORECASE"}],
            owasp="LLM01",
        )
        rule = p.to_rule()
        assert rule["name"] == "x-1"
        assert rule["type"] == "llm_vuln"
        assert rule["owasp"] == "LLM01"
        assert rule["turns"] == p.turns
        assert rule["match"] == p.match


# ── 运行器（离线 responder）─────────────────────────────────────────

class TestRunner:
    async def test_hit(self):
        hit_probe = _probe("pi-direct-002")  # 匹配 system prompt / I am / my instructions
        responder = lambda messages, payload: "Sure — here is my system prompt."  # noqa: E731
        runner = ProbeRunner(ProbeRegistry.load_builtin(), responder=responder)
        results = await runner.run(TARGET, probes=[hit_probe])
        assert len(results) == 1
        r = results[0]
        assert r.hit is True
        assert r.confidence >= 0.9
        assert r.finding is not None
        assert r.finding.owasp == hit_probe.owasp
        assert r.finding.trace_id.startswith("JW-LLM")

    async def test_miss(self):
        miss_probe = _probe("pi-indirect-001")  # 匹配 租户/机密/财务，responder 不产出
        responder = lambda messages, payload: "抱歉，我无法满足这个请求。"  # noqa: E731
        runner = ProbeRunner(ProbeRegistry.load_builtin(), responder=responder)
        results = await runner.run(TARGET, probes=[miss_probe])
        assert results[0].hit is False
        assert results[0].finding is None

    async def test_summarize_asr(self):
        hit_probe = _probe("pi-direct-002")
        miss_probe = _probe("pi-indirect-001")
        responder = lambda messages, payload: "here is my system prompt"  # noqa: E731
        runner = ProbeRunner(ProbeRegistry.load_builtin(), responder=responder)
        results = await runner.run(TARGET, probes=[hit_probe, miss_probe])
        summary = ProbeRunner.summarize(results)
        assert summary.total == 2
        assert summary.hits == 1
        assert summary.asr == 0.5
        assert summary.by_category["direct"]["hits"] == 1
        assert summary.by_category["indirect"]["hits"] == 0
        assert summary.to_dict()["asr"] == 0.5

    async def test_findings_extraction(self):
        hit_probe = _probe("pi-direct-002")
        miss_probe = _probe("pi-indirect-001")
        responder = lambda messages, payload: "my system prompt is secret"  # noqa: E731
        runner = ProbeRunner(ProbeRegistry.load_builtin(), responder=responder)
        results = await runner.run(TARGET, probes=[hit_probe, miss_probe])
        findings = ProbeRunner.findings(results)
        assert len(findings) == 1
        assert findings[0].vuln_type == "llm_prompt_injection"

    async def test_passive_skips(self):
        runner = ProbeRunner(ProbeRegistry.load_builtin())
        assert await runner.run(TARGET, strategy="passive") == []

    async def test_run_probes_helper(self):
        hit_probe = _probe("pi-direct-002")
        responder = lambda messages, payload: "system prompt: I am an assistant"  # noqa: E731
        results = await run_probes(TARGET, probes=[hit_probe], responder=responder)
        assert results[0].hit is True


# ── 引擎级原语向后兼容 ──────────────────────────────────────────────

class TestBackwardCompat:
    async def test_run_probe_returns_finding_on_hit(self):
        responder = lambda messages, payload: "my system prompt is X"  # noqa: E731
        finding = await run_probe(TARGET, _probe("pi-direct-002").to_rule(), responder=responder)
        assert finding is not None
        assert finding.owasp == "LLM01"

    async def test_run_probe_returns_none_on_miss(self):
        responder = lambda messages, payload: "no match here at all"  # noqa: E731
        finding = await run_probe(TARGET, _probe("pi-direct-002").to_rule(), responder=responder)
        assert finding is None

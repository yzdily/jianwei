"""M2 验证：动态 Scope + 流量语料（关 0903 F11 上下文虚拟化缺口）。

硬指标（见 docs/digpool_workbench_roadmap.md §4 / 0912_digpool_milestones.md §1）：
- ingest_traffic(corpus) 运行时扩界，断言 scope_after.domains ⊋ scope_before.domains。
- 事件流含 scope_updated。
- 越权扩域按 F17 授权门思想被拒绝。
"""
from __future__ import annotations

from core.digpool.scope import Scope, TrafficCorpus
from core.digpool.session import DigPoolSession, SessionPhase


async def test_ingest_traffic_expands_domains():
    # 初始 scope 仅 example.com（未设 authorized 白名单 → 开放扩界）
    session = DigPoolSession(target="https://example.com", scope={"domains": ["example.com"]})
    before = set(session.scope.domains)

    corpus = TrafficCorpus(
        source="proxy",
        domains=["api.example.com", "cdn.example.com", "evil-unrelated.com"],
    )
    update = await session.ingest_traffic(corpus)

    after = set(session.scope.domains)
    # 硬指标：scope_after.domains ⊋ scope_before.domains
    assert after > before
    # 开放扩界下三个候选域均被纳入
    assert "api.example.com" in after and "cdn.example.com" in after
    assert "evil-unrelated.com" in after
    assert update.has_change is True
    # 越权拒绝行为由 test_out_of_authorized_scope_rejected 单独验证


async def test_ingest_from_records_extracts_endpoints():
    session = DigPoolSession(target="https://example.com")
    corpus = TrafficCorpus.from_records(
        "compliance-cert",
        [
            {"host": "example.com", "url": "https://example.com/admin/users", "method": "GET"},
            {"host": "example.com", "url": "https://example.com/api/v1/token"},
        ],
    )
    update = await session.ingest_traffic(corpus)
    assert "GET /admin/users" in session.scope.endpoints or "/admin/users" in " ".join(session.scope.endpoints)
    assert update.has_change is True


async def test_event_stream_contains_scope_updated():
    session = DigPoolSession(target="https://example.com", scope={"domains": ["example.com"]})
    corpus = TrafficCorpus(source="proxy", domains=["api.example.com"])

    phases: list[str] = []
    # 直接消费 ingest 产生的事件（ingest_traffic 已 emit scope_updated）
    await session.ingest_traffic(corpus)
    phases = [ev.phase for ev in session.events]
    assert SessionPhase.SCOPE_UPDATED in phases

    # 事件 data 含 before/after 快照，且 after ⊋ before
    ev = next(e for e in session.events if e.phase == SessionPhase.SCOPE_UPDATED)
    before_domains = set(ev.data["before"]["domains"])
    after_domains = set(ev.data["after"]["domains"])
    assert after_domains > before_domains


async def test_out_of_authorized_scope_rejected():
    # 仅授权 example.com 及其子域（F17 授权门）
    session = DigPoolSession(
        target="https://example.com",
        scope={"domains": ["example.com"], "authorized": ["example.com"]},
    )
    corpus = TrafficCorpus(
        source="proxy",
        domains=["sub.example.com", "attacker.com", "phishing.net"],
    )
    update = await session.ingest_traffic(corpus)
    # 授权内子域可扩展
    assert "sub.example.com" in session.scope.domains
    # 越权域被拒
    assert "attacker.com" in update.rejected_domains
    assert "phishing.net" in update.rejected_domains
    assert "attacker.com" not in session.scope.domains

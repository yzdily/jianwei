"""DigPool 动态 Scope + 流量语料（M2 硬指标）。

对标：0912_DigPool_tech_analysis.md §2.1（动态 Scope）、§5（流量语料 vs 文本上下文）。
关 0903 遗留：F11 上下文虚拟化升级为「代理/合规证书抓包 → 语义语料 → 运行时扩界」工程闭环。

设计要点：
- `Scope` 在鉴微侧持有，支持运行时 `expand()`；扩界受 `authorized` 授权白名单约束
  （复用 F17 授权门思想：仅可在初始授权范围内收敛/扩展，越权扩域触发拒绝）。
- `TrafficCorpus` 抽象「代理/合规证书抓包 → 语义语料」的摄入；`ingest_traffic()` 把语料
  解析为域名/端点候选，驱动 `Scope` 扩界。
- 不依赖玄鉴内部类；玄鉴侧零改动。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

_HOST_RE = re.compile(r"^(?:https?://)?([\w.-]+\.[a-z]{2,})(?::\d+)?(/.*)?$", re.I)


def _extract_host(value: str) -> str | None:
    """从 URL 或裸域名中解析主机名（小写、去端口）。"""
    if not value:
        return None
    m = _HOST_RE.match(value.strip())
    if m:
        return m.group(1).lower()
    # 退路：交给 urlparse
    host = urlparse(value).hostname
    return host.lower() if host else None


def _extract_path_endpoint(value: str) -> str | None:
    """从 URL 解析「METHOD? path」形式的端点标识（缺方法时给 GET 默认）。"""
    if not value:
        return None
    m = _HOST_RE.match(value.strip())
    if m and m.group(2):
        return f"GET {m.group(2)}"
    p = urlparse(value)
    if p.path:
        return f"GET {p.path}"
    return None


@dataclass
class Scope:
    """测试范围：关联域名 + 端点 + 授权白名单（F17 思想）。"""

    domains: set[str] = field(default_factory=set)
    endpoints: set[str] = field(default_factory=set)
    authorized: set[str] = field(default_factory=set)  # 授权范围；非空时扩界必须落在其内

    # ---- 构造 / 序列化 ----
    @classmethod
    def from_dict(cls, data: dict | None) -> "Scope":
        data = data or {}
        return cls(
            domains=set(data.get("domains", [])),
            endpoints=set(data.get("endpoints", [])),
            authorized=set(data.get("authorized", [])),
        )

    def to_dict(self) -> dict:
        return {
            "domains": sorted(self.domains),
            "endpoints": sorted(self.endpoints),
            "authorized": sorted(self.authorized),
        }

    # ---- F17 授权门：判断候选是否在授权白名单内 ----
    def _is_authorized(self, candidate: str) -> bool:
        """候选域名/端点须落在 authorized 内（authorized 为空视为未设限，允许收敛/扩展）。"""
        if not self.authorized:
            return True
        c = candidate.lower()
        for a in self.authorized:
            a = a.lower()
            # 精确命中，或候选为授权域的子域
            if c == a or c.endswith("." + a):
                return True
        return False

    # ---- 运行时扩界（M2 核心）----
    def expand(
        self,
        domains: list[str] | None = None,
        endpoints: list[str] | None = None,
    ) -> "ScopeUpdate":
        """运行时扩界：在授权白名单内新增域名/端点，越权候选被拒绝。

        Args:
            domains: 候选域名列表（URL 或裸域名均可）。
            endpoints: 候选端点列表（URL 或「METHOD path」均可）。

        Returns:
            ScopeUpdate：本次新增与拒绝的集合，供事件流与测试断言。
        """
        added_domains: set[str] = set()
        rejected_domains: set[str] = set()
        added_endpoints: set[str] = set()
        rejected_endpoints: set[str] = set()

        for raw in domains or []:
            host = _extract_host(raw)
            if not host:
                continue
            if host in self.domains:
                continue
            if self._is_authorized(host):
                self.domains.add(host)
                added_domains.add(host)
            else:
                rejected_domains.add(host)

        for raw in endpoints or []:
            ep = _extract_path_endpoint(raw)
            if not ep:
                continue
            if ep in self.endpoints:
                continue
            if self._is_authorized(ep) or self._is_authorized(_extract_host(raw) or ""):
                self.endpoints.add(ep)
                added_endpoints.add(ep)
            else:
                rejected_endpoints.add(ep)

        return ScopeUpdate(
            added_domains=added_domains,
            added_endpoints=added_endpoints,
            rejected_domains=rejected_domains,
            rejected_endpoints=rejected_endpoints,
        )


@dataclass
class ScopeUpdate:
    """一次扩界的结果（新增 + 拒绝），用于事件流与测试断言。"""

    added_domains: set[str] = field(default_factory=set)
    added_endpoints: set[str] = field(default_factory=set)
    rejected_domains: set[str] = field(default_factory=set)
    rejected_endpoints: set[str] = field(default_factory=set)

    @property
    def has_change(self) -> bool:
        return bool(self.added_domains or self.added_endpoints)

    def to_dict(self) -> dict:
        return {
            "added_domains": sorted(self.added_domains),
            "added_endpoints": sorted(self.added_endpoints),
            "rejected_domains": sorted(self.rejected_domains),
            "rejected_endpoints": sorted(self.rejected_endpoints),
            "has_change": self.has_change,
        }


@dataclass
class TrafficCorpus:
    """流量语料：代理/合规证书抓包 → 语义语料。

    source 标记语料来源（如 "proxy" / "compliance-cert"）。records 为原始语义语料
    （每条可含 host / url / method / path / raw 字段）；domains / endpoints 为预提取候选。
    """

    source: str = "proxy"
    domains: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    records: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_records(cls, source: str, records: list[dict[str, Any]]) -> "TrafficCorpus":
        """从语义语料记录中解析域名/端点候选。"""
        domains: list[str] = []
        endpoints: list[str] = []
        for rec in records:
            for key in ("host", "url", "domain"):
                val = rec.get(key)
                if val:
                    domains.append(str(val))
            for key in ("url", "path", "endpoint"):
                val = rec.get(key)
                if val:
                    endpoints.append(str(val))
        return cls(source=source, domains=domains, endpoints=endpoints, records=records)

    def candidates(self) -> tuple[list[str], list[str]]:
        """返回 (domains, endpoints) 候选元组，合并预提取与 records 派生。"""
        domains = list(self.domains)
        endpoints = list(self.endpoints)
        if self.records:
            sub = self.from_records(self.source, self.records)
            domains.extend(sub.domains)
            endpoints.extend(sub.endpoints)
        # 去重保序
        seen_d, seen_e = set(), set()
        uniq_d, uniq_e = [], []
        for d in domains:
            if d not in seen_d:
                seen_d.add(d)
                uniq_d.append(d)
        for e in endpoints:
            if e not in seen_e:
                seen_e.add(e)
                uniq_e.append(e)
        return uniq_d, uniq_e


__all__ = ["Scope", "ScopeUpdate", "TrafficCorpus"]

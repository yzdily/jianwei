"""`ai` 域端点归属器（E2 · 平台 sidecar，零侵入）。

设计见《AI风险接入testflow矩阵_设计稿》§3.1：
- **只追加** `ai` 域到功能点，绝不删改引擎已归属的 8 域（保持多域并集语义）；
- 纯分析、0 请求、纯 stdlib；不 import 引擎内部有状态对象。

阶段 2（回流引擎）后，本模块由引擎原生归属取代。
"""
from __future__ import annotations

from typing import Any, Iterable

__all__ = ["AI_DOMAIN", "AIEndpointTagger"]

AI_DOMAIN = "ai"

# LLM/Agent/RAG 端点高特征关键词（小写匹配）。刻意取高区分度词，降低业务词误命中。
AI_KEYWORDS: tuple[str, ...] = (
    "chat", "completion", "completions", "converse", "inference",
    "generate", "prompt",
    "embedding", "embeddings", "vector", "rag", "retrieval", "retriever", "knowledge",
    "agent", "agents", "tool", "tools", "function_call", "function-call",
    "mcp", "plugin",
)

_STATE_CHANGING = {"POST", "PUT", "DELETE", "PATCH"}


def _endpoints_of(fp: Any) -> list[tuple[str, str]]:
    """从功能点提取 (method, path) 列表；兼容对象与 dict。"""
    apis = _get(fp, "related_apis") or []
    out: list[tuple[str, str]] = []
    for api in apis:
        parts = str(api or "").split(" ", 1)
        if len(parts) == 2:
            out.append((parts[0].upper(), parts[1].split("?")[0]))
        elif parts and parts[0]:
            out.append(("GET", parts[0].split("?")[0]))
    if not out:
        page = _get(fp, "page_url") or ""
        if page:
            out.append(("GET", str(page).split("?")[0]))
    return out


def _get(obj: Any, key: str, default: Any = None) -> Any:
    """对象或 dict 统一取值。"""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _set(obj: Any, key: str, value: Any) -> None:
    if isinstance(obj, dict):
        obj[key] = value
    else:
        setattr(obj, key, value)


class AIEndpointTagger:
    """把 LLM/Agent/RAG 端点补打 `ai` 域。"""

    def __init__(self, keywords: Iterable[str] | None = None):
        self.keywords = tuple(k.lower() for k in (keywords or AI_KEYWORDS))

    def is_ai_path(self, path: str) -> bool:
        low = (path or "").lower()
        return any(k in low for k in self.keywords)

    def is_ai_endpoint(self, path: str, method: str = "GET") -> bool:
        return self.is_ai_path(path)

    def tag(self, feature_points: Iterable[Any], sitemap: Any = None) -> dict:
        """对功能点追加 `ai` 域并初始化其 domain_status。

        Returns:
            stats：{attributed, ai_endpoints, matched_paths, via}
        """
        attributed = 0
        matched_paths: list[str] = []
        for fp in feature_points:
            hit = False
            for _method, path in _endpoints_of(fp):
                if self.is_ai_path(path):
                    hit = True
                    matched_paths.append(path)
                    break
            if not hit:
                continue

            domains = list(_get(fp, "risk_domains") or [])
            if AI_DOMAIN not in domains:
                domains.append(AI_DOMAIN)          # 只追加
            _set(fp, "risk_domains", domains)

            status = dict(_get(fp, "domain_status") or {})
            status.setdefault(AI_DOMAIN, "needs_follow_up")
            _set(fp, "domain_status", status)
            attributed += 1

        return {
            "attributed": attributed,
            "ai_endpoints": len(matched_paths),
            "matched_paths": matched_paths,
            "via": "sidecar",
        }

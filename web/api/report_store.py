"""报告/指标结果存储（可插拔后端）。

默认内存存储（开发 / 单元测试）；生产可设 `JIANWEI_REPORT_STORE=redis`
并通过 `REDIS_URL` 指向 Redis，替换进程内字典为 Redis 哈希，避免多实例
结果丢失。接口保持最小：put / get / exists。

注：当前仅实现内存后端；Redis 后端为预留接入点（依赖 redis-py，未强制安装）。
"""
from __future__ import annotations

import os
from typing import Any


class MemoryReportStore:
    """进程内结果存储（默认）。单进程 / 测试场景足够。"""

    def __init__(self):
        self._data: dict[str, dict] = {}

    def put(self, scan_id: str, payload: dict) -> None:
        self._data[scan_id] = payload

    def get(self, scan_id: str) -> dict | None:
        return self._data.get(scan_id)

    def exists(self, scan_id: str) -> bool:
        return scan_id in self._data


def _build_store() -> Any:
    """按环境变量选择存储后端。"""
    kind = os.getenv("JIANWEI_REPORT_STORE", "memory").lower()
    if kind == "redis":
        # 预留接入点：生产多实例部署时使用。
        # 需安装 redis-py：pip install redis
        url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        try:
            import redis  # type: ignore
        except ImportError:
            raise RuntimeError(
                "REDIS store 需要 redis-py，请先 `pip install redis`，"
                "或设 JIANWEI_REPORT_STORE=memory 使用内存存储。"
            )

        class RedisReportStore:
            def __init__(self, url: str):
                self._r = redis.Redis.from_url(url, decode_responses=True)

            def put(self, scan_id: str, payload: dict) -> None:
                import json
                self._r.hset("jianwei:reports", scan_id, json.dumps(payload, ensure_ascii=False))

            def get(self, scan_id: str) -> dict | None:
                import json
                raw = self._r.hget("jianwei:reports", scan_id)
                return json.loads(raw) if raw else None

            def exists(self, scan_id: str) -> bool:
                return bool(self._r.hexists("jianwei:reports", scan_id))

        return RedisReportStore(url)
    # 默认内存
    return MemoryReportStore()


# 模块级单例（应用生命周期内复用）
store = _build_store()

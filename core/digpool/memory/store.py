"""M4 · 项目级记忆（MemoryStore）—— 把一次闭环结果沉淀为可复用记忆。

对齐《鉴微优化方案 §5》M4：`VulnChainMemory` 仅内存、随会话消亡；
本模块提供**落盘的项目级记忆**，让「同类目标复用」成为可能（记忆驱动下一次任务）。

零依赖：仅用标准库 json/pathlib；默认落点 `<repo>/.digpool/`（可注入 root 便于测试）。
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Optional

from core.digpool.scope import _extract_host
from core.log import get_logger

log = get_logger("core.digpool.memory.store")


def _default_root() -> Path:
    # store.py → memory/ → digpool/ → core/ → repo root
    return Path(__file__).resolve().parents[3] / ".digpool"


def _slug(value: str) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", value or "").strip("_")
    return s or "default"


class MemoryStore:
    """项目级记忆：按 project_key 落盘运行记录，并提供 recall 供下一次任务复用。"""

    def __init__(self, root: str | Path | None = None):
        # 懒创建：仅在实际写入时落盘，避免仅构造会话就在磁盘留下空目录
        self.root = Path(root) if root else _default_root()

    # ---- 路径 ----
    @property
    def _projects_dir(self) -> Path:
        return self.root / "projects"

    @property
    def _reports_dir(self) -> Path:
        return self.root / "reports"

    def project_key_for(self, target: Optional[str], *, fallback: str = "default") -> str:
        """由目标推导项目键（域名优先，本地路径取末段）。"""
        if not target:
            return fallback
        host = _extract_host(target)
        if host:
            return _slug(host)
        name = Path(str(target)).name or str(target)
        return _slug(name) or fallback

    def _project_file(self, project_key: str) -> Path:
        return self._projects_dir / f"{_slug(project_key)}.json"

    def report_path(self, project_key: str, run_id: str) -> Path:
        d = self._reports_dir / _slug(project_key)
        d.mkdir(parents=True, exist_ok=True)
        return d / f"{_slug(run_id)}.md"

    # ---- 读写 ----
    def _load(self, project_key: str) -> dict:
        path = self._project_file(project_key)
        if not path.exists():
            return {"project": _slug(project_key), "runs": []}
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:  # 损坏记忆不应拖垮闭环
            log.warning(f"记忆文件损坏，重建: {path} ({exc})")
            return {"project": _slug(project_key), "runs": []}

    def _atomic_write(self, path: Path, payload: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(path)

    def save_run(self, project_key: str, record: dict) -> Path:
        """追加一条运行记录并落盘。"""
        data = self._load(project_key)
        record = {"ts": time.time(), **record}
        data.setdefault("runs", []).append(record)
        path = self._project_file(project_key)
        self._atomic_write(path, data)
        return path

    def save_report(self, project_key: str, run_id: str, text: str) -> Path:
        """把报告 markdown 落盘。"""
        path = self.report_path(project_key, run_id)
        path.write_text(text, encoding="utf-8")
        return path

    def history(self, project_key: str) -> list[dict]:
        return list(self._load(project_key).get("runs", []))

    def latest(self, project_key: str) -> Optional[dict]:
        runs = self.history(project_key)
        return runs[-1] if runs else None

    def recall(self, project_key: str) -> dict:
        """聚合项目记忆：供 Planner/Agent 复用「同类目标」的以往结论。"""
        runs = self.history(project_key)
        vuln_types: list[str] = []
        triggers: list[str] = []
        targets: list[str] = []
        for r in runs:
            for vt in r.get("vuln_types", []) or []:
                if vt not in vuln_types:
                    vuln_types.append(vt)
            for tg in r.get("triggers", []) or []:
                if tg not in triggers:
                    triggers.append(tg)
            t = r.get("target")
            if t and t not in targets:
                targets.append(t)
        last = runs[-1] if runs else {}
        return {
            "project": _slug(project_key),
            "run_count": len(runs),
            "known_vuln_types": vuln_types,
            "known_triggers": triggers,
            "known_targets": targets,
            "last_termination": last.get("termination"),
            "last_run_id": last.get("run_id"),
            "last_report_path": last.get("report_path"),
        }


__all__ = ["MemoryStore"]

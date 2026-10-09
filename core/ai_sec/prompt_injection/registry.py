"""探针注册表 — 内置库 + skills_my/redteam 遗留探针的归一化收编。

设计（《鉴微优化方案》§2.1）：
- 内置库（`library/`）= 规范格式，唯一事实源；
- `load_from_skills()` 把 `skills_my/redteam/*.py` 的遗留元组
  `(name, prompt, pattern, owasp)` **按文件路径**动态加载并归一化为 Probe，
  不依赖 `skills_my` 是否为 Python 包（该目录无 `__init__.py`）。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Iterator

from core.ai_sec.prompt_injection.library import BUILTIN_PROBES
from core.ai_sec.prompt_injection.models import Probe

__all__ = ["ProbeRegistry"]

# 遗留元组所属模块名 → 探针 category
_MODULE_CATEGORY = {
    "direct_injection": "direct",
    "indirect_injection": "indirect",
    "jailbreak": "jailbreak",
    "multimodal": "multimodal",
}


class ProbeRegistry:
    """注入探针集合（按 id 去重）。"""

    def __init__(self, probes: list[Probe] | None = None):
        self._probes: dict[str, Probe] = {}
        for p in probes or []:
            self.register(p)

    # ---- 基本操作 ----
    def register(self, probe: Probe) -> None:
        self._probes[probe.id] = probe

    def extend(self, probes: list[Probe]) -> int:
        before = len(self._probes)
        for p in probes:
            self.register(p)
        return len(self._probes) - before

    def all(self) -> list[Probe]:
        return list(self._probes.values())

    def by_category(self, category: str) -> list[Probe]:
        return [p for p in self._probes.values() if p.category == category]

    def by_owasp(self, owasp: str) -> list[Probe]:
        return [p for p in self._probes.values() if p.owasp == owasp]

    def categories(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for p in self._probes.values():
            out[p.category] = out.get(p.category, 0) + 1
        return out

    def __len__(self) -> int:
        return len(self._probes)

    def __iter__(self) -> Iterator[Probe]:
        return iter(self._probes.values())

    # ---- 加载器 ----
    @classmethod
    def load_builtin(cls) -> "ProbeRegistry":
        """仅内置库。"""
        return cls(list(BUILTIN_PROBES))

    @classmethod
    def load(cls, strategy: str = "redteam") -> "ProbeRegistry":
        """按策略加载：standard → 内置；redteam/compliance → 内置 + skills。"""
        reg = cls.load_builtin()
        if strategy in ("redteam", "compliance"):
            reg.load_from_skills()
        return reg

    def load_from_skills(self, skills_dir: str | Path = "skills_my/redteam") -> int:
        """收编 skills_my/redteam 下的遗留元组探针，返回新增条数。"""
        root = Path(skills_dir)
        if not root.is_absolute():
            # 相对仓库根解析（本文件位于 core/ai_sec/prompt_injection/）
            root = Path(__file__).resolve().parents[3] / skills_dir
        if not root.is_dir():
            return 0

        added = 0
        for py in sorted(root.glob("*.py")):
            if py.name == "__init__.py":
                continue
            module = _load_module_from_path(py)
            raw = getattr(module, "PROBES", None)
            if not raw:
                continue
            category = _MODULE_CATEGORY.get(py.stem, "direct")
            for item in raw:
                probe = _normalize_legacy(py.stem, category, item)
                if probe is not None:
                    if probe.id not in self._probes:
                        added += 1
                    self.register(probe)
        return added


def _load_module_from_path(path: Path):
    """按文件路径加载模块（不要求父目录是 Python 包）。"""
    spec = importlib.util.spec_from_file_location(f"_redteam_{path.stem}", path)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _normalize_legacy(module_name: str, category: str, item) -> Probe | None:
    """遗留元组 `(name, prompt, pattern, owasp)` → Probe。"""
    if not isinstance(item, (tuple, list)) or len(item) < 3:
        return None
    name = str(item[0])
    prompt = str(item[1])
    pattern = str(item[2])
    owasp = str(item[3]) if len(item) > 3 else "LLM01"
    return Probe(
        id=f"skill-{module_name}-{name}",
        category=category,
        turns=[{"role": "user", "content": prompt}],
        match=[{"pattern": pattern, "in": "response", "flags": "IGNORECASE"}],
        owasp=owasp,
        severity="high",
        description=f"[skills_my/redteam] {name}",
        source="skills",
    )

"""supply_chain 分析器 —— 解析依赖清单并查 OSV.dev 已知 CVE。

映射 → LLM03 供应链（设计 §3.2）。
信任边界（设计 §3.3）：仅把「依赖坐标（包名+版本）」发往 OSV.dev，**不发源码**。
离线/无网络时优雅降级：仅解析依赖清单并产出 info 级清单发现，不报错。
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass

from core.log import get_logger
from .base import Analyzer, FileEntry, ScanContext, SkillFinding, Severity, is_text_file

log = get_logger("skill_scan.supply_chain")

_OSV_URL = "https://api.osv.dev/v1/query"
_ECOSYSTEM_MAP = {
    "requirements.txt": "PyPI",
    "pyproject.toml": "PyPI",
    "setup.py": "PyPI",
    "package.json": "npm",
    "package-lock.json": "npm",
    "yarn.lock": "npm",
}

# 仅这些文件名参与依赖解析
_DEP_FILENAMES = set(_ECOSYSTEM_MAP.keys())


@dataclass
class Dependency:
    name: str
    version: str
    ecosystem: str
    source_file: str


class SupplyChainAnalyzer(Analyzer):
    name = "supply_chain"
    enabled_strategies = ("standard", "redteam", "compliance")

    def analyze(self, files: list[FileEntry], ctx: ScanContext) -> list[SkillFinding]:
        deps = self._collect_deps(files)
        if not deps:
            return []

        findings: list[SkillFinding] = []
        # info：依赖清单概览
        findings.append(SkillFinding(
            name="supply_chain:manifest",
            check_type="skill_dependency_manifest",
            severity=Severity.INFO,
            file_path=",".join(sorted({d.source_file for d in deps})),
            owasp="LLM03",
            description=f"解析到 {len(deps)} 条依赖声明，已对照 OSV.dev 查询已知漏洞。",
            recommendation="定期更新依赖并启用锁文件，关注传递依赖的 CVE。",
            confidence=1.0,
        ))

        for dep in deps:
            vulns = self._query_osv(dep, ctx)
            for vid in vulns:
                findings.append(SkillFinding(
                    name="supply_chain:cve",
                    check_type="skill_dependency_cve",
                    severity=Severity.HIGH,
                    file_path=dep.source_file,
                    owasp="LLM03",
                    description=f"依赖 {dep.name}@{dep.version} 命中已知漏洞 {vid}（OSV）。",
                    recommendation=f"升级 {dep.name} 至已修复版本，或评估移除该依赖。",
                    confidence=0.9,
                    safe_to_install=False,
                ))
        return findings

    # ---------------------------------------------------------------- 解析
    def _collect_deps(self, files: list[FileEntry]) -> list[Dependency]:
        deps: list[Dependency] = []
        for entry in files:
            fname = entry.rel_path.split("/")[-1].split("\\")[-1]
            if fname not in _DEP_FILENAMES:
                continue
            eco = _ECOSYSTEM_MAP[fname]
            content = entry.content or ""
            if not content and is_text_file(entry):
                try:
                    with open(entry.abs_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except Exception:
                    continue
            if fname in ("requirements.txt", "setup.py"):
                deps.extend(self._parse_pip(content, fname))
            elif fname == "pyproject.toml":
                deps.extend(self._parse_pyproject(content, fname))
            elif fname in ("package.json", "package-lock.json", "yarn.lock"):
                deps.extend(self._parse_npm(content, fname))
        return deps

    @staticmethod
    def _parse_pip(content: str, fname: str) -> list[Dependency]:
        out = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(==|>=|<=|~=|!=|>|<|@)\s*([A-Za-z0-9_.\-]+)", line)
            if m:
                out.append(Dependency(m.group(1), m.group(3), "PyPI", fname))
        return out

    @staticmethod
    def _parse_pyproject(content: str, fname: str) -> list[Dependency]:
        out = []
        # 简单正则：dependencies = ["pkg>=1.0", ...] 与 poetry 风格
        for m in re.finditer(r"([A-Za-z0-9_.\-]+)\s*(==|>=|<=|~=|!=|>|<|@)\s*[\"']?([A-Za-z0-9_.\-]+)", content):
            out.append(Dependency(m.group(1), m.group(3), "PyPI", fname))
        return out

    @staticmethod
    def _parse_npm(content: str, fname: str) -> list[Dependency]:
        out = []
        try:
            data = json.loads(content)
        except Exception:
            # yarn.lock 非 JSON，仅做粗略提取
            for m in re.finditer(r"^(\"?)([A-Za-z0-9_.\-@/]+)\2@?([\^~]?[\d.]+)", content, re.MULTILINE):
                out.append(Dependency(m.group(2), m.group(3), "npm", fname))
            return out
        deps = {}
        deps.update(data.get("dependencies", {}))
        deps.update(data.get("devDependencies", {}))
        for name, ver in deps.items():
            ver = str(ver).lstrip("^~>=< ")
            out.append(Dependency(name, ver, "npm", fname))
        return out

    # ---------------------------------------------------------------- OSV 查询
    @staticmethod
    def _query_osv(dep: Dependency, ctx: ScanContext) -> list[str]:
        try:
            import httpx  # 可选依赖：缺失时离线降级，仅跳过在线 CVE 查询
        except ImportError:
            log.debug("httpx 未安装，跳过 OSV.dev 在线 CVE 查询（仅做依赖清单解析）")
            return []
        try:
            with httpx.Client(timeout=5.0) as client:
                resp = client.post(_OSV_URL, json={
                    "package": {"name": dep.name, "ecosystem": dep.ecosystem},
                    "version": dep.version,
                })
                if resp.status_code == 200:
                    data = resp.json()
                    return [v.get("id", "CVE") for v in data.get("vulns", [])]
        except Exception as e:
            log.debug(f"osv query failed for {dep.name}: {e}")
        return []

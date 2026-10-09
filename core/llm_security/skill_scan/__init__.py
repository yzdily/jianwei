"""鉴微技能供应链静态扫描包（SkillSpector 式，动静互补）。

公开入口（单一 surface）：
  - `scan_skill(source, strategy, use_llm)` → SkillScanResult   （canonical）
  - `scan_package` = `scan_skill` 的向后兼容别名
  - `to_sarif(result)` / `render_markdown(result)` → 报告导出

  source: 本地目录 / zip / 单文件 SKILL.md / http(s) URL / git URL
  strategy: passive(清单) / standard(静态+AST+OSV) / redteam(+LLM语义) / compliance(差距清单)

设计要点：
  - 信任边界（§3.3）：绝不执行被扫对象，仅只读解析。
  - 防 zip-bomb / 路径穿越 / 扫完即焚（§4.2）。
  - 评分 0-100 + 可执行脚本 ×1.3，退出码作 CI 门禁（§3.4）。
"""
from __future__ import annotations

import time
import uuid

from core.log import get_logger
from .analyzers.base import ScanContext, SkillFinding
from .analyzers.registry import register_all, run_enabled
from .ingest import IngestResult, ingest
from .models import FileNode, SkillStrategy, SkillTarget
from .report import build_sarif, exit_code_for, render_markdown, to_sarif
from .scoring import score_findings, summarize

log = get_logger("skill_scan")

__all__ = [
    "scan_skill", "scan_package", "SkillScanResult", "SkillFinding",
    "ScanContext", "IngestResult", "register_all",
    "SkillStrategy", "SkillTarget", "FileNode",
    "to_sarif", "render_markdown", "build_sarif", "summarize",
]


class SkillScanResult:
    """技能包扫描结果。"""

    def __init__(
        self,
        scan_id: str,
        source: str,
        strategy: str,
        findings: list[SkillFinding],
        risk_score: int,
        severity: str,
        safe_to_install: bool,
    ):
        self.scan_id = scan_id
        self.source = source
        self.strategy = strategy
        self.findings = findings
        self.risk_score = risk_score
        self.severity = severity
        self.safe_to_install = safe_to_install
        self.elapsed = 0.0

    def sarif(self) -> dict:
        return to_sarif(self)

    @property
    def exit_code(self) -> int:
        return exit_code_for(self.risk_score)

    @staticmethod
    def _finding_dict(f) -> dict:
        d = f.to_dict() if hasattr(f, "to_dict") else {}
        # 统一暴露 vuln_type（base.SkillFinding 用 check_type）
        d.setdefault("vuln_type", getattr(f, "check_type", None) or getattr(f, "vuln_type", ""))
        return d

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "source": self.source,
            "strategy": self.strategy,
            "risk_score": self.risk_score,
            "severity": self.severity,
            "safe_to_install": self.safe_to_install,
            "exit_code": self.exit_code,
            "finding_count": len(self.findings),
            "findings_count": len(self.findings),
            "findings": [self._finding_dict(f) for f in self.findings],
        }


def scan_skill(
    source: str,
    strategy: str = "standard",
    use_llm: bool = False,
    ctx: ScanContext | None = None,
    keep_temp: bool = True,
    sandbox_parent: str | None = None,
) -> SkillScanResult:
    """扫描一个技能包 / MCP server 包（静态、不执行）。

    Args:
        source: 本地目录 / zip 路径 / 单文件 / URL / git URL（也接受 bytes）
        strategy: passive / standard / redteam / compliance
        use_llm: 是否启用 LLM 语义分析（仅 redteam 有效）
        ctx: 自定义扫描上下文（大小上限等）
        keep_temp: 保留临时沙箱（默认 True；None 时交由 ingest 清理）
        sandbox_parent: 临时沙箱父目录（可选，供上层隔离）

    Returns:
        SkillScanResult
    """
    register_all()
    ctx = ctx or ScanContext(strategy=strategy, use_llm=use_llm)
    ctx.strategy = strategy
    ctx.use_llm = use_llm
    if sandbox_parent:
        ctx.root_path = sandbox_parent

    scan_id = f"JW-SKILL-{uuid.uuid4().hex[:12].upper()}"
    start = time.time()

    try:
        ingest_result = ingest(source, ctx)
    except Exception as e:
        log.error(f"ingest failed for {source}: {e}")
        return SkillScanResult(scan_id, str(source), strategy, [], 0, "info", True)

    try:
        findings = run_enabled(ingest_result.files, ctx)
    finally:
        if not keep_temp:
            ingest_result.cleanup()  # 扫完即焚

    risk_score, severity, safe = score_findings(findings)
    result = SkillScanResult(scan_id, str(source), strategy, findings, risk_score, severity, safe)
    result.elapsed = time.time() - start

    log.info(
        f"skill_scan done: {source} score={risk_score} severity={severity} "
        f"findings={len(findings)} safe={safe} exit={result.exit_code}"
    )
    return result


# 向后兼容别名（旧调用方 / 文档使用 scan_package）
scan_package = scan_skill

"""Skill / 供应链静态扫描 —— 统一数据模型。

对应 818 设计文档 _checks_llm_skeleton.py 同构思路，但本包为**真实落地引擎**
（core/fast_scanner 尚未落地，故 skill_scan 先做成独立可调用模块）。

设计要点：
- 绝不在 ingest / analyze 阶段**执行**被扫包内任何代码（铁律，沿用 SkillSpector）。
- 所有 finding 可经 to_ai_risk_finding() 回流到 core.ai_sec.models.AIRiskFinding，
  与现有 L2-L5 报告系统对齐。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class SkillStrategy(str, Enum):
    """skill 目标的测试策略（复用 TestStrategy 语义，解释不同）。"""
    PASSIVE = "passive"      # 仅文件清单 + 元数据 + 依赖清单
    STANDARD = "standard"    # 静态正则 + AST + OSV（默认）
    REDTEAM = "redteam"      # standard + LLM 语义分析（M3 完整，M0 占位）
    COMPLIANCE = "compliance"  # 对照 OWASP/MITRE 出差距清单（M1/M3）


@dataclass
class FileNode:
    """规范化后的单个文件元信息（只读解析，绝不执行）。"""
    rel_path: str          # 相对根目录的路径（已规范化，无 ../）
    abs_path: str          # 沙箱内绝对路径
    size: int = 0
    is_binary: bool = False
    ext: str = ""          # 小写扩展名，无点
    executable: bool = False  # 是否为可执行脚本/二进制（风险放大器）


@dataclass
class SkillTarget:
    """被扫 skill 包的规范化表示。"""
    source: str                     # 原始传入：目录 / zip / 单文件
    kind: str                       # dir / zip / file
    root: str                       # 沙箱内的规范化根目录
    files: list[FileNode] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)  # 从 SKILL.md frontmatter 提取
    sandbox: bool = False           # 是否由本引擎创建临时沙箱（决定扫完是否即焚）


@dataclass
class SkillFinding:
    """单条 skill 安全发现。"""
    owasp: str          # LLM01 / LLM02 / LLM06 / MCP / AGENT ...
    vuln_type: str      # 检测器名，如 skill_prompt_injection
    severity: str       # critical / high / medium / low / info
    title: str
    file_path: str      # 相对路径
    line: int = 0       # 命中行号（正则/文本类）；AST 类可置 0
    snippet: str = ""   # 命中片段（<=200 chars）
    recommendation: str = ""
    confidence: float = 1.0
    safe_to_install: bool = True    # True=该发现不阻断安装（安全）；False=阻断安装

    def to_ai_risk_finding(self):
        """回流到鉴微统一 AI 风险 schema（L2-L5 共用）。"""
        from core.ai_sec.models import AIRiskFinding
        return AIRiskFinding(
            owasp=self.owasp,
            vuln_type=self.vuln_type,
            severity=self.severity,
            url=self.file_path,  # skill 无 URL，用文件路径占位
            detail=f"[{self.owasp}] {self.title}",
            evidence=self.snippet[:500],
            payload="",
            fix_suggestion=self.recommendation,
            confidence=self.confidence,
            evidence_quality="body_confirmed" if self.confidence >= 0.8 else "content_match",
            trace_id="",
            rule_tag=f"SKILL-{self.owasp}",
        )


@dataclass
class SkillScanResult:
    """skill 扫描结果。"""
    target_source: str
    strategy: str = "standard"
    findings: list[SkillFinding] = field(default_factory=list)
    risk_score: int = 0           # 0-100
    severity: str = "info"        # 综合严重级
    safe_to_install: bool = True  # <=50 通过
    file_count: int = 0
    file_tree: list = field(default_factory=list)  # 相对路径列表
    executable_count: int = 0     # 含可执行脚本/二进制数量（×1.3 倍率触发）
    elapsed: float = 0.0
    errors: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target_source": self.target_source,
            "strategy": self.strategy,
            "risk_score": self.risk_score,
            "severity": self.severity,
            "safe_to_install": self.safe_to_install,
            "file_count": self.file_count,
            "executable_count": self.executable_count,
            "finding_count": len(self.findings),
            "findings": [
                {
                    "owasp": f.owasp,
                    "vuln_type": f.vuln_type,
                    "severity": f.severity,
                    "title": f.title,
                    "file_path": f.file_path,
                    "line": f.line,
                    "snippet": f.snippet,
                    "recommendation": f.recommendation,
                    "confidence": f.confidence,
                }
                for f in self.findings
            ],
            "file_tree": self.file_tree,
            "elapsed": round(self.elapsed, 3),
            "errors": self.errors,
        }

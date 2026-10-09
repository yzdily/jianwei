"""skill_scan 分析器基类与数据模型。

所有分析器实现 `Analyzer.analyze(files, ctx)`，返回 `SkillFinding` 列表。
信任边界（设计 §3.3）：分析器**绝不执行**被扫文件，只读解析。
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class FileEntry:
    """被摄入的单个文件（规范化后的只读视图）。"""

    rel_path: str
    abs_path: str
    size: int
    is_binary: bool = False
    content: str = ""          # 文本文件内容（二进制为空）
    executable: bool = False   # 是否为可执行脚本（.py/.sh/.js 等，风险放大器）


@dataclass
class SkillFinding:
    """技能包中的一条安全风险发现。"""

    name: str
    check_type: str
    severity: Severity
    file_path: str
    line: int = 0
    owasp: str = ""
    description: str = ""
    recommendation: str = ""
    confidence: float = 0.8
    safe_to_install: bool = True
    evidence: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "check_type": self.check_type,
            "severity": self.severity.value,
            "file_path": self.file_path,
            "line": self.line,
            "owasp": self.owasp,
            "description": self.description,
            "recommendation": self.recommendation,
            "confidence": self.confidence,
            "safe_to_install": self.safe_to_install,
            "evidence": self.evidence[:300],
        }


@dataclass
class ScanContext:
    """分析器运行上下文。"""

    strategy: str = "standard"   # passive / standard / redteam / compliance
    use_llm: bool = False        # redteam 时启用语义分析
    root_path: str = ""
    max_file_bytes: int = 1 * 1024 * 1024  # 单文件 1 MiB
    max_members: int = 10_000    # 压缩包成员上限（防 zip-bomb）
    max_zip_bytes: int = 100 * 1024 * 1024  # 压缩包 100 MiB


class Analyzer(ABC):
    """分析器接口。"""

    name: str = "base"
    # 该分析器在哪些策略下运行
    enabled_strategies: tuple[str, ...] = ("standard", "redteam", "compliance")

    @abstractmethod
    def analyze(self, files: list[FileEntry], ctx: ScanContext) -> list[SkillFinding]:
        """分析文件列表，返回发现。"""
        raise NotImplementedError


def is_text_file(entry: FileEntry, max_bytes: int = 2_000_000) -> bool:
    """判断是否为可安全读取的文本文件（避免读二进制炸内存）。"""
    if entry.is_binary:
        return False
    if entry.size > max_bytes:
        return False
    if not entry.content and Path(entry.abs_path).exists():
        try:
            with open(entry.abs_path, "r", encoding="utf-8", errors="ignore") as f:
                entry.content = f.read(max_bytes + 1)
        except Exception:
            return False
    return True

"""skill_scan 评分 —— 0-100 风险分 + 严重级 + 可执行脚本 ×1.3（设计 §3.4）。"""
from __future__ import annotations

from .analyzers.base import SkillFinding, Severity

_SEV_WEIGHT = {
    Severity.CRITICAL: 100,
    Severity.HIGH: 60,
    Severity.MEDIUM: 30,
    Severity.LOW: 15,
    Severity.INFO: 5,
}

# 字符串权重（兼容 severity 为普通字符串的 finding，如上传护栏构造的发现）
_SEV_WEIGHT_STR = {
    "critical": 100, "high": 60, "medium": 30, "low": 15, "info": 5,
}

_EXEC_EXT = {".py", ".sh", ".bat", ".ps1", ".js", ".ts"}


def _sev_str(sev) -> str:
    """Severity 枚举 / 字符串 → 小写字符串。"""
    return str(getattr(sev, "value", sev)).lower()


def _weight(sev) -> int:
    return _SEV_WEIGHT_STR.get(_sev_str(sev), 0)


def score_findings(findings: list[SkillFinding]) -> tuple[int, str, bool]:
    """对发现列表评分。

    Returns:
        (risk_score 0-100, severity_label, safe_to_install)
    """
    if not findings:
        return 0, Severity.INFO.value, True

    # 最高单条严重级决定整体标签
    worst = max(findings, key=lambda f: _weight(f.severity))
    label = _sev_str(worst.severity)

    # 累加（封顶 100）
    raw = sum(_weight(f.severity) for f in findings)
    score = min(100, raw)

    # 可执行脚本放大器：含脚本类高危发现则 ×1.3
    has_exec_risk = any(
        _sev_str(f.severity) in ("critical", "high")
        and getattr(f, "file_path", "")
        and str(f.file_path).lower().endswith(tuple(_EXEC_EXT))
        for f in findings
    )
    if has_exec_risk:
        score = min(100, int(score * 1.3))

    # 安全安装判定：任一发现标记不可安装 → 整体不可安装
    safe = not any(getattr(f, "safe_to_install", True) is False for f in findings)
    return score, label, safe


def summarize(result) -> None:
    """就地重算 `result` 的 risk_score / severity / safe_to_install。

    供 upload.py 在合并护栏发现后调用；对结果类 duck-typed（只要求 `.findings`）。
    兼容 finding.severity 为 Severity 枚举或普通字符串。
    """
    findings = list(getattr(result, "findings", []) or [])
    score, label, safe = score_findings(findings)
    result.risk_score = score
    result.severity = label
    result.safe_to_install = safe
    if hasattr(result, "executable_count"):
        result.executable_count = sum(
            1 for f in findings
            if getattr(f, "file_path", "") and str(f.file_path).lower().endswith(tuple(_EXEC_EXT))
        )

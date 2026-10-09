"""yara_scan 分析器 —— 可选已知恶意载荷签名（webshell / 挖矿）。

设计 §3.2：初始可留空规则集；若环境中安装了 `yara` 则启用，否则降级为
基于扩展名黑名单 + 轻量静态特征的预筛（仅比对，不执行，见设计 §3.3 信任边界）。
"""
from __future__ import annotations

import re

from core.log import get_logger
from .base import Analyzer, FileEntry, ScanContext, SkillFinding, Severity

log = get_logger("skill_scan.yara")

# 可执行/脚本扩展名（用于二进制预筛：仅做特征比对，不运行）
EXECUTABLE_EXT = {".py", ".sh", ".bat", ".ps1", ".js", ".exe", ".dll", ".so", ".bin"}

# 极简静态特征（webshell / 挖矿指标占位，初始规则集为空，可扩展）
_HEURISTICS = [
    (rb"eval\(\s*base64_decode", "疑似 webshell（eval+base64）", Severity.CRITICAL),
    (rb"str_rot13|gzinflate", "疑似混淆 webshell 载荷", Severity.HIGH),
    (rb"xmr|monero|mining pool|stratum\+tcp", "疑似加密货币挖矿指标", Severity.HIGH),
    (rb"reverse shell|/dev/tcp/|nc -e |bash -i", "疑似反弹 shell 载荷", Severity.CRITICAL),
]


class YaraScanAnalyzer(Analyzer):
    name = "yara_scan"
    enabled_strategies = ("standard", "redteam", "compliance")

    def analyze(self, files: list[FileEntry], ctx: ScanContext) -> list[SkillFinding]:
        findings: list[SkillFinding] = []
        for entry in files:
            # 二进制 / 可执行文件：仅做特征比对（不运行）
            if entry.is_binary or entry.rel_path.lower().endswith(tuple(EXECUTABLE_EXT)):
                try:
                    with open(entry.abs_path, "rb") as f:
                        blob = f.read(5 * 1024 * 1024)
                except Exception:
                    continue
                for pattern, desc, sev in _HEURISTICS:
                    if re.search(pattern, blob, re.IGNORECASE):
                        findings.append(SkillFinding(
                            name="yara:heuristic",
                            check_type="skill_malware_heuristic",
                            severity=sev,
                            file_path=entry.rel_path,
                            owasp="",
                            description=f"[YARA 启发式] {entry.rel_path} {desc}",
                            recommendation="疑似恶意载荷，禁止安装并人工复核。",
                            confidence=0.7,
                            safe_to_install=False,
                        ))
        return findings

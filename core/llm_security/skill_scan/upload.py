"""上传接口处理器 —— 把上传字节流转为扫描（M2 护栏 + 后端）。

对应 818 设计 §4（上传接口）/ §4.2（护栏）：
- 纯函数 handle_upload(filename, data, strategy)，无 Web 框架依赖，可直接单测。
- 护栏：单文件 ≤ 1 MiB、压缩包 ≤ 100 MiB；防 zip-bomb / 路径穿越（委托 ingest 安全解包）；
  二进制预筛（仅特征标记，绝不执行）。
- 落临时沙箱 → 复用 scan_skill 跑同一引擎 → 扫完即焚。

FastAPI 路由（web/api/skill_upload.py）在上层薄封装本模块，便于挂载。
"""
from __future__ import annotations

import os
import shutil
import tempfile
import uuid
import zipfile
from pathlib import Path

from . import scan_skill
from .analyzers.base import Severity, SkillFinding
from .ingest import MAX_FILE_BYTES, MAX_ZIP_BYTES
from .models import SkillStrategy
from .scoring import summarize

# 上传态内存存储（生产可换 Redis）；scan_id -> payload
_STORE: dict[str, dict] = {}

# 直接以二进制上传的"高危可执行"扩展名（原始文件即二进制，无法静态读文本）
_BINARY_EXEC_EXTS = {
    ".exe", ".dll", ".so", ".dylib", ".bin", ".pyc", ".pyd", ".msi", ".apk",
    ".elf", ".macho", ".sh", ".bat", ".cmd", ".ps1",
}


def _is_zip_bytes(data: bytes) -> bool:
    return data[:4] == b"PK\x03\x04"


def _prescreen_binary(filename: str, data: bytes) -> SkillFinding | None:
    """原始上传文件即二进制可执行时的护栏提示（不运行，仅标记）。"""
    ext = Path(filename).suffix.lower()
    if ext in _BINARY_EXEC_EXTS:
        return SkillFinding(
            name="skill_upload_binary_exec",
            check_type="skill_upload_binary_exec",
            severity=Severity.HIGH,
            file_path=filename, line=0, owasp="MALWARE",
            description=f"直接上传了可执行二进制（{ext or '无扩展名'}），无法进行源码静态分析",
            recommendation="仅可执行二进制无法做源码审计，建议改为上传源码包（目录/zip/SKILL.md）。",
            confidence=0.9, safe_to_install=False)
    return None


def handle_upload(
    filename: str,
    data: bytes,
    strategy: str = SkillStrategy.STANDARD.value,
    sandbox_parent: str | None = None,
) -> dict:
    """处理一次上传扫描。

    Args:
        filename: 原始文件名
        data: 文件二进制内容
        strategy: passive/standard/redteam/compliance
        sandbox_parent: 临时沙箱父目录

    Returns:
        {scan_id, ...scan_skill 结果 to_dict()}

    Raises:
        ValueError: 触发护栏（体积超限 / 未知策略等）
    """
    if strategy not in {s.value for s in SkillStrategy}:
        raise ValueError(f"未知策略：{strategy}")

    # ---- 护栏：体积上限 ----
    if _is_zip_bytes(data):
        if len(data) > MAX_ZIP_BYTES:
            raise ValueError(
                f"压缩包体积超限（{len(data)} > {MAX_ZIP_BYTES} bytes），拒绝扫描（防资源耗尽）")
    else:
        if len(data) > MAX_FILE_BYTES:
            raise ValueError(
                f"单文件体积超限（{len(data)} > {MAX_FILE_BYTES} bytes），拒绝扫描")

    scan_id = uuid.uuid4().hex[:16]
    parent = Path(sandbox_parent) if sandbox_parent else Path(tempfile.gettempdir())
    upload_root = parent / f"jw_upload_{scan_id}"
    upload_root.mkdir(parents=True, exist_ok=True)

    try:
        # ---- 二进制预筛：原始上传即危险二进制 ----
        guard_findings: list[SkillFinding] = []
        bin_hint = _prescreen_binary(filename, data)
        if bin_hint:
            guard_findings.append(bin_hint)

        # ---- 落盘 ----
        safe_name = os.path.basename(filename) or "upload.bin"
        dest = upload_root / safe_name
        dest.write_bytes(data)

        # ---- 复用同一引擎扫描（zip 由 ingest 安全解包）----
        result = scan_skill(str(dest), strategy=strategy,
                            keep_temp=False, sandbox_parent=str(upload_root))

        # 合并护栏发现
        if guard_findings:
            result.findings.extend(guard_findings)
            summarize(result)

        payload = result.to_dict()
        payload["scan_id"] = scan_id
        _STORE[scan_id] = payload
        return payload
    finally:
        # 扫完即焚：清理上传沙箱根
        shutil.rmtree(upload_root, ignore_errors=True)


def store_get(scan_id: str) -> dict | None:
    return _STORE.get(scan_id)


def store_clear() -> None:
    _STORE.clear()

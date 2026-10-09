"""skill_scan 摄入层（ingest）—— 多通道归一化为只读文件树。

设计 §3.1 / §4.2：
  通道 A 本地路径 / B git URL / C 远程 URL / D zip / E 单文件 SKILL.md
  → 统一规范化文件树（只读解析）。
信任边界 & 护栏：
  - 不执行任何被摄入内容
  - 防 zip-bomb：单文件 ≤ max_file_bytes，成员 ≤ max_members，压缩包 ≤ max_zip_bytes
  - 路径穿越防护：拒绝 ../ 与绝对路径写入沙箱外
  - 扫完即焚：返回的 IngestResult.cleanup() 删除临时目录
"""
from __future__ import annotations

import io
import os
import re
import shutil
import tempfile
import zipfile
from pathlib import Path
from urllib.parse import urlparse

from core.log import get_logger
from .analyzers.base import FileEntry, ScanContext

log = get_logger("skill_scan.ingest")

# 上传/摄入护栏体积上限（供 upload.py、web 层引用；数值与 ScanContext 默认一致）
MAX_FILE_BYTES = 1 * 1024 * 1024      # 单文件 1 MiB
MAX_ZIP_BYTES = 100 * 1024 * 1024     # 压缩包 100 MiB
MAX_MEMBERS = 10_000                  # 压缩包成员上限（防 zip-bomb）

_EXEC_EXT = {".py", ".sh", ".bat", ".ps1", ".js", ".ts", ".rb", ".pl"}
_TEXT_EXT = {
    ".md", ".txt", ".yaml", ".yml", ".toml", ".json", ".jsonl", ".cfg", ".ini",
    ".py", ".js", ".ts", ".sh", ".bat", ".ps1", ".rb", ".go", ".java", ".c",
    ".cpp", ".h", ".rs", ".html", ".css", ".xml", ".csv", ".env",
}


class IngestResult:
    """摄入结果：含文件列表与临时目录（需 cleanup）。"""

    def __init__(self, root: str, files: list[FileEntry], temp_dirs: list[str]):
        self.root = root
        self.files = files
        self.temp_dirs = temp_dirs

    def cleanup(self) -> None:
        """扫完即焚：删除临时落盘目录。"""
        for d in self.temp_dirs:
            try:
                shutil.rmtree(d, ignore_errors=True)
            except Exception as e:
                log.warning(f"cleanup failed: {e}")


def _is_binary(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            chunk = f.read(8192)
    except Exception:
        return True
    if b"\x00" in chunk:
        return True
    return False


def _build_entries(root: str, max_file_bytes: int) -> list[FileEntry]:
    """遍历 root，构建 FileEntry 列表（只读、不执行）。"""
    entries: list[FileEntry] = []
    for abs_path in sorted(Path(root).rglob("*")):
        if not abs_path.is_file():
            continue
        size = abs_path.stat().st_size
        rel = str(abs_path.relative_to(root)).replace("\\", "/")
        ext = abs_path.suffix.lower()
        is_bin = _is_binary(str(abs_path)) or (ext not in _TEXT_EXT and size > 0)
        executable = ext in _EXEC_EXT
        entries.append(FileEntry(
            rel_path=rel,
            abs_path=str(abs_path),
            size=size,
            is_binary=is_bin,
            executable=executable,
        ))
    return entries


def ingest_dir(path: str, ctx: ScanContext) -> IngestResult:
    root = str(Path(path).resolve())
    files = _build_entries(root, ctx.max_file_bytes)
    log.info(f"ingest_dir: {len(files)} files from {root}")
    return IngestResult(root=root, files=files, temp_dirs=[])


def ingest_single_file(path: str, ctx: ScanContext) -> IngestResult:
    """单文件（如 SKILL.md）摄入：放到临时目录后统一处理。"""
    p = Path(path)
    tmp = tempfile.mkdtemp(prefix="skill_scan_")
    dest = os.path.join(tmp, p.name)
    shutil.copy2(str(p), dest)
    files = _build_entries(tmp, ctx.max_file_bytes)
    return IngestResult(root=tmp, files=files, temp_dirs=[tmp])


def ingest_zip(path_or_bytes, ctx: ScanContext) -> IngestResult:
    """解包 zip（含防 zip-bomb + 路径穿越防护）。"""
    tmp = tempfile.mkdtemp(prefix="skill_scan_")
    try:
        if isinstance(path_or_bytes, (bytes, bytearray)):
            data = io.BytesIO(bytes(path_or_bytes))
        else:
            src = Path(path_or_bytes)
            if src.stat().st_size > ctx.max_zip_bytes:
                raise ValueError(f"zip too large: {src.stat().st_size} > {ctx.max_zip_bytes}")
            data = open(str(src), "rb")
        with zipfile.ZipFile(data) as zf:
            names = zf.namelist()
            if len(names) > ctx.max_members:
                raise ValueError(f"too many members: {len(names)} > {ctx.max_members}")
            for name in names:
                # 路径穿越防护
                if name.startswith("/") or ".." in name.split("/"):
                    log.warning(f"skipping unsafe path in zip: {name}")
                    continue
                info = zf.getinfo(name)
                if info.file_size > ctx.max_file_bytes:
                    log.warning(f"skipping oversized member: {name} ({info.file_size})")
                    continue
                if name.endswith("/"):
                    continue
                zf.extract(name, tmp)
        files = _build_entries(tmp, ctx.max_file_bytes)
        log.info(f"ingest_zip: {len(files)} files")
        return IngestResult(root=tmp, files=files, temp_dirs=[tmp])
    except Exception as e:
        shutil.rmtree(tmp, ignore_errors=True)
        raise ValueError(f"zip ingest failed: {e}") from e


def ingest_url(url: str, ctx: ScanContext) -> IngestResult:
    """远程 URL 下载到沙箱（限大小）。需网络；失败抛异常由调用方处理。"""
    import httpx
    tmp = tempfile.mkdtemp(prefix="skill_scan_")
    try:
        with httpx.Client(timeout=30.0, follow_redirects=True) as client:
            with client.stream("GET", url) as resp:
                if resp.status_code != 200:
                    raise ValueError(f"download failed: HTTP {resp.status_code}")
                dest = os.path.join(tmp, "download")
                total = 0
                with open(dest, "wb") as f:
                    for chunk in resp.iter_bytes():
                        total += len(chunk)
                        if total > ctx.max_zip_bytes:
                            raise ValueError("download exceeds size limit")
                        f.write(chunk)
        # 按扩展名决定后续处理
        if dest.endswith((".zip", ".tar.gz", ".tgz")):
            return ingest_zip(dest, ctx)
        return ingest_single_file(dest, ctx)
    except Exception:
        shutil.rmtree(tmp, ignore_errors=True)
        raise


def ingest_git(url: str, ctx: ScanContext) -> IngestResult:
    """git clone 到沙箱（--depth 1）。需 git 与网络。"""
    import subprocess
    tmp = tempfile.mkdtemp(prefix="skill_scan_")
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", url, tmp + "/repo"],
            check=True, timeout=120, capture_output=True,
        )
        return ingest_dir(tmp + "/repo", ctx)
    except Exception:
        shutil.rmtree(tmp, ignore_errors=True)
        raise


def ingest(source: str | bytes | bytearray, ctx: ScanContext) -> IngestResult:
    """统一摄入入口，按 source 形态自动分派。

    Args:
        source: 本地路径 / zip 路径 / 单文件路径 / http(s) URL / git URL / 原始 bytes
        ctx: 扫描上下文（含大小上限）
    """
    if isinstance(source, (bytes, bytearray)):
        return ingest_zip(source, ctx)
    if isinstance(source, str) and re.match(r"^https?://", source):
        return ingest_url(source, ctx)
    if isinstance(source, str) and re.match(r"^(git@|https?://.*\.git$|git://)", source):
        return ingest_git(source, ctx)
    if not os.path.exists(source):
        raise FileNotFoundError(f"source not found: {source}")
    if os.path.isfile(source):
        if source.lower().endswith((".zip", ".tar.gz", ".tgz")):
            return ingest_zip(source, ctx)
        return ingest_single_file(source, ctx)
    return ingest_dir(source, ctx)

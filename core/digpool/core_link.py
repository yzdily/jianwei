"""鉴微 ↔ 玄鉴引擎的连接缝（core_link）。

设计纪律（见 ARCHITECTURE.md）：
- 鉴微平台层（L1-L5）**复用**玄鉴 XuanJian v2.0 引擎（L0），
  依赖通过 requirements.txt 的 `xuanjian @ git+https://github.com/yzdily/xuanjian@v2.0` 引入。
- 鉴微**绝不修改、绝不 patch、绝不 subclass 玄鉴内部类**，只能经其公开包边界调用。
- 本模块是唯一的「引擎边界」接触点：优先链接真实 xuanjian；不可用时降级为 StubCore，
  保证 M0 脚手架在任意环境（含未 pip 安装 xuanjian 的开发机）都能跑通。

M0「空跑通」语义：passthrough() 不发射任何真实攻击，仅验证「已能触达 xuanjian 公开入口」，
并声明 boundary_intact=True（边界完整、未破引擎边界）。
"""
from __future__ import annotations

import importlib
from typing import Any, Optional, Protocol, runtime_checkable

from core.log import get_logger

log = get_logger("core.digpool.core_link")


@runtime_checkable
class CoreBackend(Protocol):
    """DigPoolSession 依赖的引擎后端最小契约。"""

    backend_name: str

    async def open_session(self, session_id: str, target: Optional[str], scope: dict) -> Any:
        ...

    async def passthrough(self, handle: Any) -> dict:
        """M0 空跑：验证边界完整，不发射攻击。返回含 mode 的字典。"""
        ...

    async def close_session(self, handle: Any) -> None:
        ...


class StubCore:
    """本地兜底后端：xuanjian 未安装时启用，保证 M0 跑通。

    仅用于开发期脚手架验证，**不可用于真实扫描**。
    """

    backend_name = "stub"

    async def open_session(self, session_id: str, target: Optional[str], scope: dict) -> dict:
        return {"session_id": session_id, "target": target, "scope": scope, "kind": "stub"}

    async def passthrough(self, handle: Any) -> dict:
        return {"mode": "stub", "entry": None, "note": "xuanjian 未链接，使用本地兜底后端"}

    async def close_session(self, handle: Any) -> None:
        return None


class XuanjianCore:
    """真实引擎后端：组合（非继承）xuanjian 公开入口。

    不破边界：只持有入口引用，绝不在运行时 monkey-patch 玄鉴源码。
    """

    backend_name = "xuanjian"

    def __init__(self, entry: Any):
        self._entry = entry

    async def open_session(self, session_id: str, target: Optional[str], scope: dict) -> dict:
        # M0：仅记录会话句柄，不调用引擎的攻击执行路径
        entry_name = (
            f"{getattr(self._entry, '__module__', '')}"
            f".{getattr(self._entry, '__name__', self._entry)}"
        )
        return {
            "session_id": session_id,
            "target": target,
            "scope": scope,
            "kind": "xuanjian",
            "entry": entry_name,
        }

    async def passthrough(self, handle: Any) -> dict:
        # M0 空跑：确认已能触达玄鉴公开入口即视为边界完整；不进入攻击执行。
        entry = handle.get("entry") if isinstance(handle, dict) else str(self._entry)
        return {
            "mode": "xuanjian",
            "entry": entry,
            "note": "已链接引擎，边界完整（未发射攻击）",
        }

    async def close_session(self, handle: Any) -> None:
        return None


def _probe_xuanjian_entry() -> Optional[Any]:
    """探测玄鉴 v2.0 公开入口；找不到则返回 None（降级 stub）。"""
    try:
        import xuanjian  # noqa: F401  v2.0（requirements 已声明）
    except Exception as exc:  # 未安装 / 网络离线
        log.info(f"xuanjian 引擎不可用，降级 StubCore: {exc}")
        return None

    # 已知公共候选入口（以玄鉴 v2.0 公开 API 为准）。任意一个命中即视为已链接。
    candidates = (
        "xuanjian.core.session",
        "xuanjian.core.orchestrator",
        "xuanjian.core.fast_scanner",
    )
    for modname in candidates:
        try:
            mod = importlib.import_module(modname)
        except Exception:
            continue
        for attr in ("Session", "Orchestrator", "FastScanner", "ChatLoop"):
            entry = getattr(mod, attr, None)
            if entry is not None:
                log.info(f"已链接 xuanjian 入口: {modname}.{attr}")
                return entry
    log.info("xuanjian 已导入但无已知公开入口，降级 StubCore")
    return None


_ENTRY = _probe_xuanjian_entry()
CORE_LINKED: bool = _ENTRY is not None


def get_core_backend() -> CoreBackend:
    """返回当前环境可用的最佳后端（真实引擎优先，否则 stub）。"""
    if CORE_LINKED:
        return XuanjianCore(_ENTRY)  # type: ignore[arg-type]
    return StubCore()


# ============================================================================
# LOOP 引擎桥梁（M3 钩入点）：同样只经玄鉴公开包边界调用，绝不修改引擎循环体。
# ============================================================================

_LOOP_CONTROLLER_CLS: type | None = None
_LOOP_CTL_PROBED = False


def _probe_xuanjian_loop_controller() -> type | None:
    """探测上游 LoopController 公开类；缺失则返回 None（退回 vendored mirror）。

    严格只 import 公开包路径 `xuanjian.core.loops.loop_controller.LoopController`，
    不触碰任何玄鉴内部模块。
    """
    try:
        import xuanjian  # noqa: F401
    except Exception:
        return None
    try:
        from xuanjian.core.loops.loop_controller import LoopController as XJLoop  # type: ignore
        return XJLoop  # type: ignore[return-value]
    except Exception:
        return None


def get_loop_controller() -> type:
    """返回可用的 LoopController 类（真实引擎优先，否则 vendored mirror）。

    调用方负责实例化；实例化时若未显式传入 vuln_chain，会自动用 vendored
    VulnChainMemory（仅作去重/审计存储，不影响引擎执行语义）。
    """
    global _LOOP_CONTROLLER_CLS, _LOOP_CTL_PROBED
    if _LOOP_CTL_PROBED:
        return _LOOP_CONTROLLER_CLS  # type: ignore[return-value]
    _LOOP_CTL_PROBED = True
    real = _probe_xuanjian_loop_controller()
    if real is not None:
        _LOOP_CONTROLLER_CLS = real
        log.info("已链接上游 LoopController（xuanjian.core.loops.loop_controller）")
        return real  # type: ignore[return-value]
    # 退回 vendored mirror（开发/测试环境）
    from core.digpool.loops.loop_controller import LoopController as MirrorLoop  # type: ignore
    _LOOP_CONTROLLER_CLS = MirrorLoop
    log.info("上游 LoopController 不可用，退回 vendored mirror（core.digpool.loops）")
    return MirrorLoop  # type: ignore[return-value]

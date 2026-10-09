"""MCP stdio Server —— 零依赖暴露 scan_skill 工具（M3 收口）。

对应 818 设计 §5（Agent 集成）：让玄鉴 agent（或任意兼容 MCP 的客户端）在
安装/调用第三方 skill 之前先自审，闭合「供应链安全」回路。

实现要点：
- **零依赖**：纯 stdlib（json/sys）实现 MCP stdio 传输（换行分隔 JSON-RPC 2.0），
  不依赖 `mcp` SDK —— 任何 MCP client（Claude Desktop / Cursor / 自研 agent）可直接挂载。
- 方法支持：initialize / notifications:initialized / ping / tools/list / tools/call。
- 工具实现复用 mcp_tool.scan_skill_tool()（扫描铁律：绝不执行被扫包内代码）。

运行：
    python -m core.llm_security.skill_scan.mcp_server
（客户端以 stdio 方式拉起本进程即可）
"""
from __future__ import annotations

import json
import sys

from .mcp_tool import as_mcp_tool_def, dispatch

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "jianwei-skill-scan", "version": "1.0"}

# 不需要回包的 notification 方法
_NOTIFICATIONS = {"notifications/initialized", "notifications/cancelled"}


def _result(req_id, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _error(req_id, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def handle_message(msg: dict) -> dict | None:
    """处理单条 JSON-RPC 消息；notification 返回 None（无回包）。"""
    method = msg.get("method", "")
    req_id = msg.get("id")
    params = msg.get("params") or {}

    if method in _NOTIFICATIONS:
        return None

    if method == "initialize":
        return _result(req_id, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": SERVER_INFO,
        })

    if method == "ping":
        return _result(req_id, {})

    if method == "tools/list":
        return _result(req_id, {"tools": [as_mcp_tool_def()]})

    if method == "tools/call":
        name = params.get("name", "")
        arguments = params.get("arguments") or {}
        try:
            out = dispatch(name, arguments)
        except KeyError:
            return _error(req_id, -32602, f"工具参数缺失：{name} 需要 target")
        except Exception as e:
            return _result(req_id, {
                "content": [{"type": "text", "text": json.dumps(
                    {"error": f"{type(e).__name__}: {e}"}, ensure_ascii=False)}],
                "isError": True,
            })
        return _result(req_id, {
            "content": [{"type": "text",
                         "text": json.dumps(out, ensure_ascii=False)}],
            "isError": False,
        })

    if req_id is None:
        # 未知 notification：静默忽略
        return None
    return _error(req_id, -32601, f"method not found: {method}")


def serve(stdin=sys.stdin, stdout=sys.stdout) -> None:
    """stdio 主循环：逐行读 JSON-RPC，逐行写回包。"""
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            resp = _error(None, -32700, "parse error")
        else:
            resp = handle_message(msg)
        if resp is not None:
            stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            stdout.flush()


if __name__ == "__main__":
    serve()

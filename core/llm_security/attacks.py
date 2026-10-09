"""LLM 攻击发射库 — 按 YAML 规则向目标 LLM 发对抗 prompt。

对应 818 设计文档 §3.3 数据流中的 attacks 模块。
依赖 httpx 直接发 HTTP 请求到目标 LLM 端点（非鉴微自身模型）。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

try:
    from core.log import get_logger
except Exception:
    import logging
    def get_logger(name): return logging.getLogger(name)

log = get_logger("llm_security.attacks")


@dataclass
class AttackResult:
    """单次攻击发射的结果。"""
    response_text: str = ""
    tool_results: list[str] = field(default_factory=list)
    status_code: int = 0
    elapsed: float = 0.0
    error: str = ""


def fill_vars(template: str, target: Any) -> str:
    """填充 prompt 模板中的变量占位符。

    支持的占位符：{target_host} {target_url} {secret_hint} 等。
    """
    vals = {
        "target_host": getattr(target, "url", ""),
        "target_url": getattr(target, "url", ""),
        "secret_hint": "LLMVAULT",
    }
    extra = getattr(target, "extra", {})
    if isinstance(extra, dict):
        vals.update({k: str(v) for k, v in extra.items()})
    try:
        return template.format(**vals)
    except (KeyError, IndexError):
        return template


async def fire_attack(target: Any, rule: dict, timeout: float = 30.0,
                      responder: Any | None = None) -> AttackResult:
    """按 rule 的 turns 序列向目标 LLM 发请求，返回最终响应。

    对应 818 _checks_llm_skeleton.py 中的 fire_attack 调用。

    Args:
        target: ScanTarget-like 对象，含 url / headers / extra["llm"]
        rule: YAML 规则字典，含 turns / tool_trigger 等
        timeout: 单次 HTTP 请求超时
        responder: 可选离线响应函数 (messages, payload) -> str，
                   提供时跳过真实 HTTP（用于单测与靶场 mock）
    """
    result = AttackResult()
    url = getattr(target, "url", "")
    headers = getattr(target, "headers", {}) or {}
    turns = rule.get("turns", [])

    if not turns:
        result.error = "no turns defined in rule"
        return result

    messages = []
    for turn in turns:
        content = fill_vars(turn.get("content", ""), target)
        messages.append({
            "role": turn.get("role", "user"),
            "content": content,
        })

    payload = {
        "model": getattr(target, "extra", {}).get("llm", {}).get("model", "default"),
        "messages": messages,
        "temperature": 0.7,
    }
    if rule.get("tool_trigger"):
        payload["tools"] = getattr(target, "extra", {}).get("llm", {}).get("tools", [])

    # 离线响应器（测试 / 靶场 mock）：跳过真实 HTTP
    if responder is not None:
        try:
            text = responder(messages, payload)
            result.response_text = text if isinstance(text, str) else str(text)
            result.status_code = 200
        except Exception as e:
            result.error = str(e)
        return result

    try:
        import httpx  # 懒加载：仅发射真实 HTTP 时才需要，离线/无依赖环境不强制
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(url, json=payload, headers=headers)
            result.status_code = resp.status_code
            result.response_text = resp.text

            if resp.status_code == 200:
                try:
                    data = resp.json()
                    choices = data.get("choices", [])
                    if choices:
                        msg = choices[0].get("message", {})
                        result.response_text = msg.get("content", "")
                        tool_calls = msg.get("tool_calls", [])
                        for tc in tool_calls:
                            result.tool_results.append(str(tc))
                except Exception:
                    pass
    except httpx.TimeoutException:
        result.error = "timeout"
        log.warning(f"attack timeout: {url}")
    except Exception as e:
        result.error = str(e)
        log.error(f"attack error: {e}")

    return result

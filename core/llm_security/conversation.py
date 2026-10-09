"""多轮对话驱动器 — 支持高级越狱 / 二阶注入的多轮编排。

对应 818 设计文档 §3.2 conversation.py，覆盖 Advanced 10 类多轮实验。
"""
from __future__ import annotations

from typing import Any

try:
    from core.log import get_logger
except Exception:
    import logging
    def get_logger(name): return logging.getLogger(name)

from .attacks import AttackResult, fill_vars

log = get_logger("llm_security.conversation")


class MultiTurnDriver:
    """多轮对话驱动器：按 turns 序列逐轮发送，维护对话上下文。"""

    def __init__(self, target: Any, timeout: float = 30.0):
        self.target = target
        self.timeout = timeout
        self.history: list[dict] = []

    async def run_turns(self, turns: list[dict]) -> AttackResult:
        """按 turns 序列逐轮发送，返回最终结果。"""
        import httpx

        result = AttackResult()
        url = getattr(self.target, "url", "")
        headers = getattr(self.target, "headers", {}) or {}
        model = getattr(self.target, "extra", {}).get("llm", {}).get("model", "default")

        for turn in turns:
            content = fill_vars(turn.get("content", ""), self.target)
            self.history.append({
                "role": turn.get("role", "user"),
                "content": content,
            })

            payload = {
                "model": model,
                "messages": list(self.history),
                "temperature": 0.7,
            }

            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    resp = await client.post(url, json=payload, headers=headers)
                    result.status_code = resp.status_code
                    if resp.status_code == 200:
                        try:
                            data = resp.json()
                            choices = data.get("choices", [])
                            if choices:
                                msg = choices[0].get("message", {})
                                result.response_text = msg.get("content", "")
                                self.history.append({
                                    "role": "assistant",
                                    "content": result.response_text,
                                })
                                tool_calls = msg.get("tool_calls", [])
                                for tc in tool_calls:
                                    result.tool_results.append(str(tc))
                        except (ValueError, KeyError, TypeError) as e:
                            log.warning(f"parse error: {e}")
                    else:
                        result.error = f"HTTP {resp.status_code}"
                        break
            except httpx.TimeoutException:
                result.error = "timeout"
                break
            except Exception as e:
                result.error = str(e)
                break

        return result

    def reset(self):
        self.history.clear()

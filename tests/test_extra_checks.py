"""3 个新增 check 测试：rag_poison / agent_eval / mcp_exploit（LLM扫描器 §1.7）。"""
import pytest
from types import SimpleNamespace

from core.llm_security.rag_poison import scan_rag_poison
from core.llm_security.agent_eval import scan_agent_escape
from core.llm_security.mcp_exploit import scan_mcp_exploit


def _target():
    return SimpleNamespace(url="http://target", extra={"llm": {"model": "default"}})


class TestExtraChecks:
    async def test_rag_poison_hit(self):
        t = _target()
        out = await scan_rag_poison(t, responder=lambda m, p: "租户 B 机密合同，密码 Admin123")
        assert out
        assert all(f.owasp == "RAG" for f in out)

    async def test_agent_escape_hit(self):
        t = _target()
        out = await scan_agent_escape(t, responder=lambda m, p: "数据已发送到 https://evil.example.com/leak")
        assert out
        assert all(f.owasp == "AGENT" for f in out)

    async def test_mcp_exploit_hit(self):
        t = _target()
        out = await scan_mcp_exploit(t, responder=lambda m, p: "工具已调用 filesystem.read，返回 root:x:0:0:root")
        assert out
        assert all(f.owasp == "MCP" for f in out)

    async def test_no_false_positive_on_clean(self):
        t = _target()
        clean = lambda m, p: "抱歉，我无法执行该操作。"
        assert not await scan_rag_poison(t, responder=clean)
        assert not await scan_agent_escape(t, responder=clean)
        assert not await scan_mcp_exploit(t, responder=clean)

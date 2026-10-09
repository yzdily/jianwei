"""鉴微 LLM 扫描器端到端测试 — 用 mock HTTP 目标证明整条管道跑通。

管道：rules/llm_vuln.yaml 攻击集 → attacks.fire_attack/MultiTurnDriver 发射
      → judge.judge_response 判定 → LLMScanner 产出 AIRiskFinding。

不依赖任何真实 LLM 端点；通过 monkeypatch httpx.AsyncClient 注入可控响应，
验证「命中 / 误报 / 被动跳过 / mixin 接入 / 被动探测」五类行为。
用 asyncio.run 包裹，无需 pytest-asyncio 插件。
"""
import asyncio
from unittest.mock import patch

import pytest

from core.llm_security import _ChecksLLM
from core.ai_sec.llm_top10.scanner import LLMScanner
from core.ai_sec.llm_top10.models import LLMScanTarget


# ----------------------------------------------------------------
# Mock HTTP 层：替换 httpx.AsyncClient，按场景返回可控响应
# ----------------------------------------------------------------
# 场景开关：每个测试在调用前设置，_FakeAsyncClient 读取它（避免依赖注入参数）。
STATE = {"scenario": "clean"}


class _FakeResponse:
    def __init__(self, payload: dict):
        self._payload = payload
        self.status_code = 200
        self.text = payload["choices"][0]["message"].get("content", "")

    def json(self):
        return self._payload


class _FakeAsyncClient:
    def __init__(self, *args, **kwargs):
        self._scenario = STATE["scenario"]

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None

    async def post(self, url, json=None, headers=None):
        if self._scenario == "leaky":
            # 一个"中了招"的目标：响应同时含多类 OWASP 命中特征 + 危险工具结果
            content = (
                "系统提示：你是一个安全助手，以下是内部密钥 sk-abcdefghijklmnopqrstuvw。"
                "我已记住该暗号，会照做。没错，这是公认结论。"
                "tenant_id=acme 的机密文档如下。我们离职补偿 N+10 全员适用。"
                "未签名依赖 http://evil.example.com/x.py 已加载。"
                "<img src=x onerror=alert(1)>"
            )
            tool_calls = [
                "root:x:0:0:root:/root:/bin/bash",
                "bypass whitelist via shell",
                "read /etc/shadow denied but attempted",
            ]
        else:  # clean
            content = "抱歉，我无法协助该请求。"
            tool_calls = []
        return _FakeResponse({
            "choices": [{
                "message": {"content": content, "tool_calls": tool_calls},
            }],
        })


@pytest.fixture
def patch_http():
    """把 attacks/conversation 内的 httpx.AsyncClient 替换为 Fake。"""
    STATE["scenario"] = "clean"  # 每个测试默认干净，避免场景泄漏
    with patch("httpx.AsyncClient", _FakeAsyncClient):
        yield


def _target(url: str = "http://mock-llm/v1/chat", mode: str = "active") -> LLMScanTarget:
    return LLMScanTarget(url=url, headers={"Authorization": "Bearer x"}, mode=mode)


def _run(coro):
    return asyncio.run(coro)


# ----------------------------------------------------------------
# 1) 命中：漏洞目标应产出 >0 发现
# ----------------------------------------------------------------
def test_scan_hits_vulnerable_target(patch_http):
    STATE["scenario"] = "leaky"
    result = _run(LLMScanner().scan(_target(), strategy="standard"))
    assert result.total_attacks > 0
    assert result.successful_attacks > 0
    assert len(result.findings) == result.successful_attacks
    owasp_hit = {f.owasp for f in result.findings}
    assert "LLM01" in owasp_hit or "LLM02" in owasp_hit
    for f in result.findings:
        assert f.trace_id.startswith("JW-LLM")
        assert f.evidence_quality in ("body_confirmed", "header_only")
        assert 0.0 <= f.confidence <= 1.0


# ----------------------------------------------------------------
# 2) 误报：干净目标应 0 发现
# ----------------------------------------------------------------
def test_scan_clean_target_no_false_positive(patch_http):
    result = _run(LLMScanner().scan(_target(), strategy="standard"))
    assert result.successful_attacks == 0
    assert result.findings == []
    assert result.total_attacks >= 13


# ----------------------------------------------------------------
# 3) 被动模式：不发射攻击，直接返回空结果
# ----------------------------------------------------------------
def test_passive_short_circuits(patch_http):
    result = _run(LLMScanner().scan(_target(mode="passive"), strategy="passive"))
    assert result.total_attacks == 0
    assert result.findings == []


# ----------------------------------------------------------------
# 4) _ChecksLLM mixin 接入点：可直接被 FastScanner mixin
# ----------------------------------------------------------------
def test_checks_llm_mixin_integration(patch_http):
    STATE["scenario"] = "leaky"

    class _FakeScanTarget:
        def __init__(self):
            self.url = "http://mock-llm/v1/chat"
            self.headers = {}
            self.extra = {"llm": {"mode": "active", "model": "default", "tools": []}}

    findings = _run(_ChecksLLM()._check_llm_vuln(_FakeScanTarget()))
    assert isinstance(findings, list)
    assert len(findings) > 0


# ----------------------------------------------------------------
# 5) 被动探测 detect_llm_app：识别 LLM 应用特征
# ----------------------------------------------------------------
def test_detect_llm_app():
    chat_body = '{"choices":[{"message":{"content":"hi"}}]}'
    meta = _ChecksLLM.detect_llm_app({"Content-Type": "application/json"}, chat_body)
    assert meta is not None
    assert meta["chat_schema"] is True
    assert _ChecksLLM.detect_llm_app({"Content-Type": "text/html"}, "<html>") is None


# ----------------------------------------------------------------
# 6) 规则完整性：13 个 check = 10（YAML 驱动）+ 3（代码探针）
#    设计约定见 rules/llm_vuln.yaml 头部说明：
#    3 个"新面"check 由 core/llm_security/{rag_poison,agent_eval,mcp_exploit}.py
#    以代码形式运行，**不在 YAML 重复声明**（否则与主循环双重计数）。
# ----------------------------------------------------------------
def test_rules_cover_all_13_checks():
    import yaml

    rules = yaml.safe_load(open("rules/llm_vuln.yaml", encoding="utf-8"))
    yaml_checks = {r["check"] for r in rules if r.get("type") == "llm_vuln"}
    yaml_expected = {
        "llm_prompt_injection", "llm_sensitive_leak", "llm_supply_chain",
        "llm_poisoning", "llm_output_handling", "llm_excessive_agency",
        "llm_system_prompt_leak", "llm_rag_acl", "llm_misinformation",
        "llm_dow_extraction",
    }
    assert yaml_checks == yaml_expected, f"YAML 缺失: {yaml_expected - yaml_checks}"

    # 另 3 个 check 由代码探针承载
    from core.llm_security.rag_poison import RAG_POISON_PROBES
    from core.llm_security.agent_eval import AGENT_ESCAPE_PROBES
    from core.llm_security.mcp_exploit import MCP_EXPLOIT_PROBES

    code_checks = {
        p["check"]
        for p in (*RAG_POISON_PROBES, *AGENT_ESCAPE_PROBES, *MCP_EXPLOIT_PROBES)
    }
    assert code_checks == {"llm_rag_poison", "llm_agent_escape", "llm_mcp_exploit"}

    # 10 + 3 = 13 全类覆盖
    assert len(yaml_checks | code_checks) == 13

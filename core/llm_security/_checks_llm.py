"""_ChecksLLM —— LLM 应用漏洞检测 mixin，零侵入接入 FastScanner 分发机制。

接入方式（待 core/fast_scanner/ 落地后）：
  1) from core.llm_security._checks_llm import _ChecksLLM
  2) class FastScanner(_ChecksInjection, _ChecksServer, _ChecksAuth,
                       _SitemapIntegration, _ChecksLLM):
  3) 在 scan_target() 的 all_rules 默认列表追加 "llm_vuln"

目标约定（由资产发现阶段填充到 target.extra["llm"]）：
  target.url            聊天/补全接口
  target.headers        含鉴权（Bearer / Cookie）
  target.extra["llm"]  {"mode": "active"/"passive", "model": ..., "tools": [...], "chat_schema": ...}

本 mixin 是**真实可用实现**（非骨架）：封装 core.ai_sec.llm_top10.LLMScanner，
把 OWASP LLM Top 10 + Agent/MCP 新面的 13 个 check 接入统一扫描分发。
判定/发射/评分逻辑复用 core.llm_security.{attacks,judge,conversation,scoring}，
攻击序列来自 rules/llm_vuln.yaml（数据驱动）。
"""
from __future__ import annotations

from typing import Any

try:
    from core.log import get_logger
except Exception:
    import logging
    def get_logger(name):  # type: ignore
        return logging.getLogger(name)

from core.ai_sec.models import AIRiskFinding
from core.ai_sec.llm_top10.scanner import LLMScanner
from core.ai_sec.llm_top10.models import LLMScanTarget

log = get_logger("llm_security.checks_llm")

# 被动探测阶段给目标打的标签（供策略引擎默认启用 llm_vuln）。
LLM_APP_TAG = "llm_app"


class _ChecksLLM:
    """LLM 应用漏洞检测 mixin：把 LLMVault 的 OWASP LLM Top 10 实验转化为扫描 check。"""

    # 缓存的扫描器实例（规则文件只加载一次）。
    _llm_scanner: LLMScanner | None = None

    # ----------------------------------------------------------
    # 入口：被 FastScanner.scan_target 经 getattr(self, "_check_llm_vuln") 分发
    # ----------------------------------------------------------
    async def _check_llm_vuln(self, target: Any) -> list[AIRiskFinding]:
        """LLM 漏洞检测主入口。

        返回统一 AI 风险发现（AIRiskFinding），可直接经
        convert_findings_to_checklist_results 回流到 orchestrator → sitemap → 报告。
        """
        findings: list[AIRiskFinding] = []

        llm_meta = getattr(target, "extra", {}).get("llm", {}) if hasattr(target, "extra") else {}
        if not llm_meta.get("mode"):
            # 未识别为 LLM 应用 → 跳过（被动模式不强制）
            return findings

        llm_target = self._adapt_target(target, llm_meta)
        strategy = "redteam" if llm_meta.get("mode") == "active" else "standard"

        if self._llm_scanner is None:
            self._llm_scanner = LLMScanner()

        result = await self._llm_scanner.scan(llm_target, strategy=strategy)
        findings.extend(result.findings)

        log.info(
            f"_check_llm_vuln done: {result.successful_attacks}/{result.total_attacks} "
            f"hits, ASR={result.asr:.1%}"
        )
        return findings

    # ----------------------------------------------------------
    # 目标适配：把 FastScanner 的 ScanTarget 适配为 LLMScanTarget
    # ----------------------------------------------------------
    @staticmethod
    def _adapt_target(target: Any, llm_meta: dict) -> LLMScanTarget:
        """从通用 target 抽取 LLM 扫描所需字段。"""
        return LLMScanTarget(
            url=getattr(target, "url", ""),
            headers=getattr(target, "headers", {}) or {},
            model=llm_meta.get("model", "default"),
            mode="active" if llm_meta.get("mode") == "active" else "passive",
            tools=llm_meta.get("tools", []) or [],
            chat_schema=llm_meta.get("chat_schema"),
            auth=llm_meta.get("auth"),
        )

    # ----------------------------------------------------------
    # 被动探测：识别 LLM 应用特征（由 crawler/business_understanding 调用）
    # ----------------------------------------------------------
    @staticmethod
    def detect_llm_app(response_headers: dict, body: str) -> dict | None:
        """从响应特征判断目标是否为 LLM 应用，返回 llm_meta 或 None。

        判定信号（源自 LLMVault Live/Play 接口形态）：
          - Content-Type 含 application/json 且 body 含 "choices"/"completion"/"message"
          - 暴露 "tools" schema（函数定义）
          - 响应回声系统提示片段
        """
        import json
        ctype = (response_headers or {}).get("Content-Type", "")
        if "json" in ctype and any(
            k in body for k in ("choices", "completion", "message", '"tools"')
        ):
            try:
                data = json.loads(body)
                tools = data.get("tools") or (
                    data.get("choices", [{}])[0].get("message", {}).get("tool_calls")
                )
            except Exception:
                tools = None
            return {"mode": "passive", "tools": tools, "chat_schema": True}
        return None

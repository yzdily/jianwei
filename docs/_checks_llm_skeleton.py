"""_ChecksLLM —— FastScanner 的新 mixin 骨架（零侵入接入示范）。

接入方式（在 core/fast_scanner/_engine.py）：
  1) from ._checks_llm import _ChecksLLM
  2) class FastScanner(_ChecksInjection, _ChecksServer, _ChecksAuth,
                       _SitemapIntegration, _ChecksLLM):
  3) 在 scan_target() 的 all_rules 默认列表追加 "llm_vuln"

本文件为方案骨架，方法体给出关键逻辑伪代码与调用关系，便于评审与后续实现。
真实实现依赖 core/llm_security 包（attacks/judge/conversation/tool_abuse）。
"""

from __future__ import annotations

from core.log import get_logger
from ._models import VulnFinding, ScanTarget

log = get_logger("fast_scanner.llm")


class _ChecksLLM:
    """LLM 应用漏洞检测 mixin：把 LLMVault 的 OWASP LLM Top 10 实验转化为扫描 check。"""

    # ----------------------------------------------------------
    # 入口：被 FastScanner.scan_target 经 getattr(self, "_check_llm_vuln") 分发
    # ----------------------------------------------------------
    async def _check_llm_vuln(self, target: ScanTarget) -> list[VulnFinding]:
        """LLM 漏洞检测主入口。

        target 需携带 LLM 应用信息（由资产发现阶段填充）：
          target.url           聊天/补全接口
          target.headers       含鉴权（Bearer / Cookie）
          target.extra["llm"]  {"mode": "active"/"passive", "tools": [...], "chat_schema": ...}
        """
        findings: list[VulnFinding] = []

        llm_meta = getattr(target, "extra", {}).get("llm", {})
        if not llm_meta.get("mode"):
            # 未识别为 LLM 应用 → 跳过（被动模式不强制）
            return findings

        # 1) 读取 YAML 攻击集（复用现有 load_rules_from_yaml("rules")，按 type=llm_vuln 过滤）
        attack_rules = [r for r in self._yaml_rules if r.get("type") == "llm_vuln"]

        # 2) 逐规则发射 + 判定
        for rule in attack_rules:
            rule_findings = await self._fire_llm_attack(target, rule)
            findings.extend(rule_findings)

        return findings

    # ----------------------------------------------------------
    # 单条攻击的发射与判定
    # ----------------------------------------------------------
    async def _fire_llm_attack(self, target: ScanTarget, rule: dict) -> list[VulnFinding]:
        """按 rule 的 turns 序列向目标 LLM 发请求，并判定是否中招。

        关键依赖（已实现，待对接）：
          - core.llm.LLMClient      向目标 LLM 端点发对话（而非 XuanJian 自身模型）
          - core.llm_security.attacks.fire()   构造/填充 prompt 变量，发多轮，收响应
          - core.llm_security.judge.judge()     确定性正则 + 可选 LLM-as-judge
        """
        from core.llm_security.attacks import fire_attack
        from core.llm_security.judge import judge_response

        # 发射攻击序列，拿到 (最后响应, 工具结果列表)
        last_response, tool_results = await fire_attack(target, rule)

        # 判定
        hit, evidence, confidence = judge_response(rule, last_response, tool_results)
        if not hit:
            return []

        # 组装 VulnFinding（沿用现有 schema，自动获得 trace_id/evidence_quality）
        return [VulnFinding(
            vuln_type=rule.get("check", "llm_vuln"),
            severity=rule.get("severity", "high"),
            url=target.url,
            method="POST",  # LLM 端点多为 POST
            detail=f"[{rule.get('owasp')}] {rule.get('description','')}",
            evidence=evidence[:500],
            payload=str(rule.get("turns")),
            fix_suggestion=rule.get("fix", ""),
            evidence_quality="body_confirmed" if confidence >= 0.8 else "header_only",
            rule_tag=f"LLM-{rule.get('owasp','')}",
        )]

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
        if "json" in ctype and any(k in body for k in ("choices", "completion", "message", "\"tools\"")):
            try:
                data = json.loads(body)
                tools = data.get("tools") or (data.get("choices", [{}])[0]
                                              .get("message", {}).get("tool_calls"))
            except Exception:
                tools = None
            return {"mode": "passive", "tools": tools, "chat_schema": True}
        return None


# ============================================================
# 接入点改动清单（供实现阶段参考，勿直接粘贴覆盖现有文件）
# ============================================================
#
# --- core/fast_scanner/_engine.py ---
#   from ._checks_llm import _ChecksLLM
#   class FastScanner(_ChecksInjection, _ChecksServer, _ChecksAuth,
#                      _SitemapIntegration, _ChecksLLM):
#       ...
#   # 在 scan_target() 的 all_rules 默认列表追加：
#   all_rules = enabled_rules or [
#       "sql_injection", "xss", ..., "jwt",
#       "llm_vuln",          # ← 新增
#   ]
#
# --- core/llm_security/attacks.py（新增包，伪代码）---
#   async def fire_attack(target, rule) -> (str, list[str]):
#       client = LLMClient(target_llm_config)   # 指向目标 LLM 端点，非本机模型
#       msgs = [Message(role=t["role"], content=fill_vars(t["content"], target))
#               for t in rule["turns"]]
#       resp = await client.chat(msgs)
#       return resp.text, resp.tool_results
#
# --- core/llm_security/judge.py（新增包，伪代码）---
#   def judge_response(rule, response, tool_results) -> (bool, str, float):
#       for m in rule.get("match", []):
#           hay = response if m["in"]=="response" else "\n".join(tool_results)
#           if re.search(m["pattern"], hay, flags=...):
#               return True, matched_snippet, 0.9
#       if rule.get("judge"):
#           return llm_judge(rule, response)     # LLM-as-judge 二次确认
#       return False, "", 0.0

"""LLM 漏洞扫描器 — 鉴微 L2 层核心能力。

对应 818 设计文档 _checks_llm_skeleton.py 的完整实现。
加载 rules/llm_vuln.yaml 攻击集，逐规则发射 + 判定。
"""
from __future__ import annotations

import time
from pathlib import Path

try:
    from core.log import get_logger
except Exception:
    import logging
    def get_logger(name): return logging.getLogger(name)

from core.llm_security.attacks import fire_attack, AttackResult
from core.llm_security.judge import judge_response
from core.llm_security.conversation import MultiTurnDriver
from core.llm_security.scoring import ScoringCard, make_trace_id
from core.ai_sec.models import AIRiskFinding
from .models import LLMScanTarget, LLMScanResult

log = get_logger("ai_sec.llm_top10")

RULES_PATH = Path(__file__).parent.parent.parent.parent / "rules" / "llm_vuln.yaml"


class LLMScanner:
    """LLM 漏洞扫描器：加载 YAML 攻击集 -> 逐规则发射 -> 判定 -> 产出 AIRiskFinding。"""

    def __init__(self, rules_path: Path | None = None):
        self.rules_path = rules_path or RULES_PATH
        self._rules: list[dict] = []
        self._load_rules()

    def _load_rules(self):
        """加载 rules/llm_vuln.yaml 攻击规则。"""
        import yaml
        if not self.rules_path.exists():
            log.warning(f"rules file not found: {self.rules_path}")
            return
        with open(self.rules_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if data and isinstance(data, list):
            self._rules = [r for r in data if r.get("type") == "llm_vuln"]
        log.info(f"loaded {len(self._rules)} LLM attack rules")

    async def scan(self, target: LLMScanTarget, strategy: str = "standard") -> LLMScanResult:
        """对目标 LLM 执行扫描。

        Args:
            target: LLM 扫描目标
            strategy: passive(只识别) / standard(全量) / redteam(主动红队)
        """
        result = LLMScanResult(target_url=target.url)
        start = time.time()

        if strategy == "passive":
            result.elapsed = time.time() - start
            return result

        for rule in self._rules:
            result.total_attacks += 1
            attack_result = await self._run_single_attack(target, rule)

            hit, evidence, confidence = judge_response(
                rule, attack_result.response_text, attack_result.tool_results
            )

            if hit:
                result.successful_attacks += 1
                finding = self._build_finding(target, rule, evidence, confidence, attack_result)
                result.findings.append(finding)
                log.info(f"hit: {rule.get('name')} ({rule.get('owasp')})")

            result.rules_run += 1

        # 3 个新增 check（§1.7）：RAG 投毒 / Agent 逃逸 / MCP 滥用
        # 仅在非 passive 时运行；干净目标不产生发现，不影响误报率
        if strategy in ("standard", "redteam"):
            extra = await self._run_extra_checks(target)
            for f in extra:
                result.findings.append(f)
                result.successful_attacks += 1
                result.total_attacks += 1

        result.elapsed = time.time() - start
        log.info(f"scan done: {result.successful_attacks}/{result.total_attacks} hits, ASR={result.asr:.1%}")
        return result

    async def _run_extra_checks(self, target: LLMScanTarget) -> list:
        """运行 RAG 投毒 / Agent 逃逸 / MCP 滥用 三个新增 check。"""
        from core.llm_security.rag_poison import scan_rag_poison
        from core.llm_security.agent_eval import scan_agent_escape
        from core.llm_security.mcp_exploit import scan_mcp_exploit

        out: list = []
        for fn in (scan_rag_poison, scan_agent_escape, scan_mcp_exploit):
            try:
                out.extend(await fn(target))
            except Exception as e:
                log.warning(f"extra check {fn.__name__} failed: {e}")
        return out

    async def _run_single_attack(self, target: LLMScanTarget, rule: dict) -> AttackResult:
        """执行单条攻击规则。"""
        turns = rule.get("turns", [])
        if len(turns) > 1:
            driver = MultiTurnDriver(target)
            return await driver.run_turns(turns)
        else:
            return await fire_attack(target, rule)

    def _build_finding(
        self,
        target: LLMScanTarget,
        rule: dict,
        evidence: str,
        confidence: float,
        attack_result: AttackResult,
    ) -> AIRiskFinding:
        """构建 AI 风险发现。"""
        owasp = rule.get("owasp", "")
        check = rule.get("check", "llm_vuln")
        return AIRiskFinding(
            owasp=owasp,
            vuln_type=check,
            severity=rule.get("severity", "high"),
            url=target.url,
            detail=f"[{owasp}] {rule.get('description', '')}",
            evidence=evidence[:500],
            payload=str(rule.get("turns", ""))[:200],
            fix_suggestion=rule.get("fix", ""),
            confidence=confidence,
            evidence_quality="body_confirmed" if confidence >= 0.8 else "header_only",
            trace_id=make_trace_id(owasp, check),
            rule_tag=f"LLM-{owasp}",
            attack_turns=rule.get("turns", []),
            response_snippet=attack_result.response_text[:300],
        )

    @staticmethod
    def detect_llm_app(response_headers: dict, body: str) -> dict | None:
        """从响应特征判断目标是否为 LLM 应用（被动探测）。"""
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

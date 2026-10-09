"""_ChecksWeb —— FastScanner 的传统 Web/Agent 基础检查。

说明：玄鉴引擎提供完整 15 条 Web 规则（sql_injection/xss/.../jwt）。
鉴微平台层在其之上**新增** AI-native 检查（llm_vuln / skill_scan / asset_discovery）。
此处实现平台层应自管的 2 个基础检查：security_headers（真实可跑）、asset_discovery（被动资产识别）。
未在本层实现的 web 规则名由 FastScanner 优雅跳过（上游引擎提供）。
"""
from __future__ import annotations

import httpx

from core.log import get_logger
from ._models import ScanTarget, VulnFinding
from ._checks_llm import _ChecksLLM

log = get_logger("fast_scanner.web")

_RECOMMENDED_HEADERS = {
    "Content-Security-Policy": "high",
    "X-Content-Type-Options": "medium",
    "X-Frame-Options": "medium",
    "Strict-Transport-Security": "high",
    "Referrer-Policy": "low",
}


class _ChecksWeb:
    """平台层基础 Web 检查 + 被动资产发现。"""

    async def _check_security_headers(self, target: ScanTarget) -> list[VulnFinding]:
        """检查响应缺失的安全响应头（真实可跑的被动检查）。"""
        if not target.url:
            return []
        findings: list[VulnFinding] = []
        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                resp = await client.get(target.url, headers=target.headers)
        except Exception as e:
            log.warning(f"security_headers fetch failed: {e}")
            return []

        for header, sev in _RECOMMENDED_HEADERS.items():
            if header not in resp.headers:
                findings.append(VulnFinding(
                    vuln_type="missing_security_header",
                    severity=sev,
                    url=str(resp.url),
                    method="GET",
                    detail=f"响应缺失安全头 {header}",
                    fix_suggestion=f"添加 `{header}` 响应头以加固浏览器侧防护。",
                    evidence_quality="header_only",
                    rule_tag="WEB-headers",
                ))
        return findings

    async def _check_asset_discovery(self, target: ScanTarget) -> list[VulnFinding]:
        """被动资产发现：识别目标是否为 LLM 应用 / 技能包，打标签。

        passive 模式下唯一运行的规则；不发射任何攻击 payload。
        """
        findings: list[VulnFinding] = []
        if target.target_type == "skill" or target.skill_meta:
            findings.append(VulnFinding(
                vuln_type="skill_package",
                severity="info",
                url=target.url or target.skill_meta.get("path", ""),
                method="STATIC",
                detail="识别为技能包/供应链扫描目标，建议用 skill_scan 规则做静态审计。",
                evidence_quality="content_match",
                rule_tag="ASSET-skill",
            ))
            return findings

        # 尝试被动识别 LLM 应用特征
        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                resp = await client.get(target.url, headers=target.headers)
            body = resp.text
            llm_meta = _ChecksLLM.detect_llm_app(dict(resp.headers), body)
        except Exception:
            return findings

        if llm_meta:
            target.extra.setdefault("llm", llm_meta)
            target.tags.append("llm_app")
            findings.append(VulnFinding(
                vuln_type="llm_app_detected",
                severity="info",
                url=target.url,
                method="GET",
                detail="响应特征表明目标为 LLM 应用（暴露 chat/tool schema），建议启用 llm_vuln 规则。",
                evidence_quality="content_match",
                rule_tag="ASSET-llm",
                owasp="LLM01",
            ))
        return findings

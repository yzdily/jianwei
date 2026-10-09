"""_ChecksSkill —— FastScanner 的新 mixin 骨架（零侵入接入示范，与 _checks_llm_skeleton.py 同构）。

接入方式（待 core/fast_scanner/_engine.py 落地后）：
  1) from core.llm_security.skill_scan._checks_skill import _ChecksSkill
  2) class FastScanner(_ChecksInjection, _ChecksLLM, _ChecksSkill): ...
  3) 在 scan_target() 的 all_rules 默认列表追加 "skill_scan"

本文件为方案骨架。M0 阶段 core/fast_scanner 尚未落地，故 skill_scan 作为独立引擎运行；
此 mixin 预留，便于未来 FastScanner 经 getattr(self, "_check_skill_scan") 分发。
"""
from __future__ import annotations

from core.llm_security.skill_scan.models import SkillFinding


class _ChecksSkill:
    """Skill / 供应链静态扫描 mixin：在侦察阶段先审第三方 skill 源码。"""

    async def _check_skill_scan(self, target) -> list[SkillFinding]:
        """skill 静态扫描主入口。

        target 需携带 skill 源信息（由资产发现阶段填充）：
          target.extra["skill_source"]  本地目录 / zip / 单文件路径
          或 target.url 作为兜底

        返回 SkillFinding 列表；调用方可用 f.to_ai_risk_finding() 回流到 AIRiskFinding。
        """
        from core.llm_security.skill_scan.ingest import ingest, cleanup
        from core.llm_security.skill_scan.registry import run
        from core.llm_security.skill_scan.scoring import summarize
        from core.llm_security.skill_scan.models import SkillScanResult

        extra = getattr(target, "extra", {}) or {}
        src = extra.get("skill_source") or getattr(target, "url", "")
        if not src:
            return []

        st = ingest(src)
        findings, errors = run(st, "standard")
        res = SkillScanResult(
            target_source=src, strategy="standard",
            findings=findings, errors=errors,
            file_count=len(st.files),
            file_tree=[f.rel_path for f in st.files],
            executable_count=sum(1 for f in st.files if f.executable),
        )
        summarize(res)
        cleanup(st)
        return findings


# ============================================================
# 接入点改动清单（供 FastScanner 落地实现阶段参考）
# ============================================================
# --- core/fast_scanner/_engine.py ---
#   from core.llm_security.skill_scan._checks_skill import _ChecksSkill
#   class FastScanner(_ChecksInjection, _ChecksServer, _ChecksAuth,
#                      _SitemapIntegration, _ChecksLLM, _ChecksSkill):
#       ...
#   # 在 scan_target() 的 enabled_rules 默认列表追加：
#   enabled_rules = [...] + ["skill_scan"]
#   # 当 target_type == "skill" 时，仅启用 ["skill_scan"]，不触发 llm_vuln

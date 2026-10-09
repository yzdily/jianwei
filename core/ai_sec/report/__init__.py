"""JianWei L5 报告层（平台层新增，不修改上游 xuanjian）。

导出 OWASP LLM Top 10 章节、MITRE ATLAS 映射、SARIF 2.1.0 导出，
以及**完整合规报告**组装（覆盖矩阵 + 详情 + PoC + 整改清单 + 等保对齐）。
设计依据：818/AI安全测试平台_MASTER_PLAN.md §11.5 L5 报告/合规层；
        818/鉴微优化方案_2026-10-08.md §4。
"""
from .llm_top10_chapter import (
    OWASP_LLM_TOP10_META,
    build_llm_top10_chapter,
    build_llm_top10_sarif,
    build_report,
    group_by_class,
)
from .atlas_chapter import (
    ATLAS_MAPPING,
    ATLAS_META_VERSION,
    build_atlas_chapter,
)
from .compliance_report import (
    OWASP_TO_DENGBAO,
    build_coverage_matrix_section,
    build_full_report,
    build_poc_section,
    build_remediation_section,
)

__all__ = [
    "OWASP_LLM_TOP10_META",
    "build_llm_top10_chapter",
    "build_llm_top10_sarif",
    "build_report",
    "group_by_class",
    "ATLAS_MAPPING",
    "ATLAS_META_VERSION",
    "build_atlas_chapter",
    "build_full_report",
    "build_coverage_matrix_section",
    "build_poc_section",
    "build_remediation_section",
    "OWASP_TO_DENGBAO",
]

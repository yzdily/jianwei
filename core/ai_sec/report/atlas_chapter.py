"""L5 报告章节 —— MITRE ATLAS 映射（鉴微平台层报告，设计 §11.5）。

把 OWASP LLM Top 10 (2025) 各类 + JianWei 三个新面映射到 MITRE ATLAS
（Adversarial Threat Landscape for Artificial-Intelligence Systems）的
战术 / 技术，便于威胁情报对齐与攻防知识图谱化。

映射依据：MITRE ATLAS v5.4.0（2026-02 更新，16 战术 / 84+ 技术，新增
"Publish Poisoned AI Agent Tool" / "Escape to Host" 等 Agent/MCP 面向技术）。
技术 ID 取自 MITRE ATLAS 公开矩阵与社区引用；如与最新官方矩阵有出入，
以 https://atlas.mitre.org/ 为准。

消费平台统一 schema `AIRiskFinding`（core.ai_sec.models）。
不修改上游 xuanjian 的 `compliance_report.py`，作为 JianWei 平台层新增模块。
单测见 tests/test_atlas_report.py。
"""
from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from core.ai_sec.models import AIRiskFinding

_ATLAS_VERSION = "v5.4.0"
ATLAS_META_VERSION = _ATLAS_VERSION

# OWASP LLM Top 10 类 / JianWei 新面 -> [(tactic, technique_id, technique_name)]
# 一个类可映射到多条 ATLAS 技术（覆盖不同攻击路径）。
ATLAS_MAPPING: dict[str, list[tuple[str, str, str]]] = {
    "LLM01": [
        ("Initial Access (TA0003)", "AML.T0051", "Prompt Injection（含直接/间接子技术）"),
    ],
    "LLM02": [
        ("Exfiltration (TA0013)", "AML.T0048", "LLM Artifact / 敏感信息抽取"),
        ("Exfiltration (TA0013)", "AML.T0132", "Exfiltration via ML Inference API"),
    ],
    "LLM03": [
        ("Initial Access (TA0003)", "AML.T0009", "ML Supply Chain Compromise"),
        ("Resource Development (TA0002)", "AML.T0019", "Publish Poisoned Datasets"),
        ("Resource Development (TA0002)", "AML.T0058", "Publish Poisoned Models"),
    ],
    "LLM04": [
        ("ML Attack Staging (TA0012)", "AML.T0020", "Poison Training Data"),
        ("ML Attack Staging (TA0012)", "AML.T0021", "Backdoor ML Model（后门训练）"),
    ],
    "LLM05": [
        ("Impact (TA0014)", "AML.T0051", "通过模型输出注入（SSRF/XSS 经工具执行）"),
    ],
    "LLM06": [
        ("Execution (TA0005)", "AML.T0054", "LLM Plugin Compromise（插件/工具劫持）"),
        ("Exfiltration (TA0013)", "AML.T0131", "Exfiltration via AI Agent Tool Invocation"),
    ],
    "LLM07": [
        ("Defense Evasion (TA0008)", "AML.T0056", "LLM Meta Prompt Extraction"),
    ],
    "LLM08": [
        ("Collection (TA0011)", "AML.T0011", "Data from Information Repositories（含 RAG 库）"),
        ("Discovery (TA0010)", "AML.T0010", "Discovery of AI Agent Configuration / RAG 索引"),
    ],
    "LLM09": [
        ("Resource Development (TA0002)", "AML.T0060", "Publish Hallucinated Entities（诱导采信幻觉）"),
    ],
    "LLM10": [
        ("ML Model Access (TA0004)", "AML.T0043", "Inference API Access（资源耗尽/DoS）"),
        ("Impact (TA0014)", "AML.T0149", "Resource Exhaustion（失控消耗）"),
    ],
    "RAG": [
        ("Resource Development (TA0002)", "AML.T0066", "Retrieval Content Crafting（检索内容投毒）"),
        ("ML Attack Staging (TA0012)", "AML.T0020", "Poison Training Data（知识库投毒）"),
    ],
    "AGENT": [
        ("Privilege Escalation (TA0007)", "AML.TXXXX", "Escape to Host（Agent 逃逸到宿主，v5.4.0 新增）"),
        ("Exfiltration (TA0013)", "AML.T0131", "Exfiltration via AI Agent Tool Invocation"),
        ("Resource Development (TA0002)", "AML.T0078", "Publish Poisoned AI Agent Tool（v5.4.0 新增）"),
    ],
    "MCP": [
        ("Execution (TA0005)", "AML.T0054", "LLM Plugin Compromise（MCP 工具链劫持）"),
        ("Resource Development (TA0002)", "AML.T0078", "Publish Poisoned AI Agent Tool（MCP 工具投毒）"),
    ],
}


def build_atlas_chapter(
    findings: Iterable[AIRiskFinding] | None = None,
    title: str = "MITRE ATLAS 映射（AI 对抗威胁景观）",
) -> str:
    """生成 ATLAS 映射章节 markdown。

    - 始终渲染 13 类 → ATLAS 战术/技术的完整对照表（静态知识）。
    - 若传入 findings，额外标注本次扫描命中的类别。
    """
    detected = set()
    if findings:
        for f in findings:
            if f.owasp:
                detected.add(f.owasp)

    lines = [f"## {title}", ""]
    lines.append(f"> 依据 MITRE ATLAS {_ATLAS_VERSION}（{len(ATLAS_MAPPING)} 类已映射）。"
                 f" 技术 ID 以 https://atlas.mitre.org/ 官方矩阵为准。")
    lines.append("")
    lines.append("| OWASP 类 | ATLAS 战术 | 技术 ID | 技术名称 |")
    lines.append("|----------|-----------|---------|----------|")
    for code in ATLAS_MAPPING:
        flag = " ✅命中" if code in detected else ""
        for tactic, tid, tname in ATLAS_MAPPING[code]:
            lines.append(f"| {code}{flag} | {tactic} | {tid} | {tname} |")
            flag = ""  # 同一类多行只在首行标 ✅
    lines.append("")
    if detected:
        lines.append(f"_本次扫描命中 {len(detected)} 个 ATLAS 相关类别：{', '.join(sorted(detected))}_")
        lines.append("")
    else:
        lines.append("_本次扫描未检出与上述 ATLAS 技术对应的风险。_")
        lines.append("")
    return "\n".join(lines)

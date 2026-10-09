"""MCP 工具：scan_skill —— 让 agent 在安装/调用第三方 skill 前自审（M3）。

对应 818 设计 §5（Agent 集成）/ M3 路线图：
- 暴露一个框架无关的 scan_skill 工具：SCAN_SKILL_TOOL_SCHEMA（MCP 工具 schema）+ scan_skill_tool() handler。
- 不绑定具体 MCP server 框架：任何兼容 MCP 的 server 只需把本 schema 注册为 tool，
  并把调用转发到 scan_skill_tool() 即可（同步封装，便于非 async 宿主）。
- 信任边界：扫描过程绝不执行被扫包内代码（沿用 skill_scan 铁律）。
"""
from __future__ import annotations

from . import scan_skill
from .report import to_sarif

# MCP 工具 schema（与常见 MCP server 的 tools 注册格式对齐）
SCAN_SKILL_TOOL_SCHEMA = {
    "name": "scan_skill",
    "description": (
        "在采纳/安装第三方 agent skill 或 MCP server 包之前，对其源码做静态安全扫描"
        "（提示注入、数据外泄、依赖 CVE、恶意签名、可执行脚本风险等）。"
        "绝不执行被扫包内代码。返回风险评分、严重级与是否可安全安装。"
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "skill 包路径：本地目录 / zip / 单文件 SKILL.md 或脚本",
            },
            "use_llm": {
                "type": "boolean",
                "description": "是否启用 LLM 语义分析（降误报 + 意图检测）。true 时策略用 redteam，否则 standard。",
                "default": False,
            },
            "output_format": {
                "type": "string",
                "enum": ["json", "sarif", "text"],
                "description": "输出格式。sarif 用于 CI/IDE 接入。",
                "default": "json",
            },
        },
        "required": ["target"],
    },
}


def scan_skill_tool(
    target: str,
    use_llm: bool = False,
    output_format: str = "json",
) -> dict:
    """scan_skill 工具 handler（同步）。

    Returns:
        根据 output_format 返回：
          - json  : SkillScanResult.to_dict()
          - sarif : SARIF 2.1.0 dict
          - text  : {"report": markdown 文本}
    """
    strategy = "redteam" if use_llm else "standard"
    result = scan_skill(target, strategy=strategy, keep_temp=True)

    if output_format == "sarif":
        return to_sarif(result)
    if output_format == "text":
        from .report import render_markdown
        return {"report": render_markdown(result)}
    return result.to_dict()


# ---- 适配各 MCP 框架的辅助 ----
def as_mcp_tool_def() -> dict:
    """返回可直接注册到 MCP server 的 tool 定义（含 name/description/inputSchema）。"""
    return {
        "name": SCAN_SKILL_TOOL_SCHEMA["name"],
        "description": SCAN_SKILL_TOOL_SCHEMA["description"],
        "inputSchema": SCAN_SKILL_TOOL_SCHEMA["inputSchema"],
    }


def dispatch(name: str, arguments: dict) -> dict:
    """MCP server 调用入口：name 命中则执行，否则返回未注册。"""
    if name != "scan_skill":
        return {"error": f"未知工具：{name}"}
    return scan_skill_tool(
        target=arguments["target"],
        use_llm=bool(arguments.get("use_llm", False)),
        output_format=arguments.get("output_format", "json"),
    )

"""鉴微 JianWei AI 安全测试平台 - 启动入口。"""
import sys
import importlib

BANNER = """
╔══════════════════════════════════════════════════════════╗
║  鉴微 JianWei - AI 安全测试平台                            ║
║  由玄鉴 XuanJian v2.0 引擎驱动（持续维护）                   ║
║  「见微知著，洞见 AI 之险」                                  ║
╚══════════════════════════════════════════════════════════╝
"""

def check_python():
    if sys.version_info < (3, 10):
        print("[ERROR] Python >= 3.10 required")
        sys.exit(1)
    print(f"[OK] Python {sys.version.split()[0]}")

def check_deps():
    deps = ["httpx", "yaml", "fastapi"]
    for dep in deps:
        try:
            importlib.import_module(dep)
            print(f"[OK] {dep}")
        except ImportError:
            print(f"[MISS] {dep} (pip install {dep})")

def main():
    # 带子命令参数时转发到 CLI（如：python start.py scan-skill ./skill/）
    if len(sys.argv) > 1:
        from core.cli import main as cli_main
        sys.exit(cli_main(sys.argv[1:]))

    print(BANNER)
    check_python()
    check_deps()
    print()
    print("  平台状态：L0(玄鉴引擎，持续维护)，L2/L3/L4/L5 平台层已落地")
    print("  架构层级：L0(玄鉴引擎) -> L1(资产) -> L2(攻击) -> L3(护栏) -> L4(度量) -> L5(报告)")
    print()
    print("  可用模块：")
    print("    - core/llm_security/  (L2 攻击库 + 判定引擎)")
    print("    - core/ai_sec/llm_top10/  (L2 OWASP LLM Top 10 扫描器)")
    print("    - core/ai_sec/sec_shield/  (L3 护栏引擎)")
    print("    - core/ai_sec/metrics/  (L4 评测度量)")
    print("    - skills_my/redteam/  (红队 Prompt 注入测试集)")
    print("    - rules/llm_vuln.yaml  (LLM 攻击规则集)")
    print()
    print("  Web API: 已就绪（/api/scan, /api/scan/skill, /api/ai-sec）")
    print("  TODO: 完整靶场集成 + 多轮/工具滥用样本扩充")
    print("=" * 60)

if __name__ == "__main__":
    main()

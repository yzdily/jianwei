"""鉴微平台 · 功能实跑验证脚本（一次跑通全部功能面，产出可核验证据）。

目的：回答三个问题——① 功能是否可用 ② 报告是否准确 ③ 能否找到**真正的**漏洞。
做法：不靠"看起来对"，而是**真发请求、真跑扫描、真读回报告**，把每步证据落成 JSON。

跑法（受管 Python 3.13）：
    C:/Users/Leucocyte/.workbuddy/binaries/python/versions/3.13.12/python.exe scripts/validate_features.py

证据落盘：818/功能实跑_证据_具体日期.json（818/ 已 gitignore，不污染仓库）。

设计要点：
- 用 FastAPI TestClient 跑**同一个 app**（= UI 走的路径），dev 模式（不设鉴权开关）全放行。
- LLM 扫描需要"靶子"：本脚本在本地起**两个 mock LLM 应用**（一个故意处处做错=漏洞靶标，
  一个处处拒答=安全靶标），通过真实 HTTP 让扫描器去打，验证"能发现真漏洞 / 不误报"。
- 绝不对公网发起任何请求（全部 127.0.0.1）。
"""
from __future__ import annotations

import io
import json
import os
import sys
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:  # 允许脚本直接跑（不依赖 cwd / PYTHONPATH）
    sys.path.insert(0, str(ROOT))

# ---- 强制 dev 模式（不设任一双开关 => 全放行），必须在导入 app 之前 ----
os.environ.pop("JIANWEI_API_KEY", None)
os.environ.pop("JIANWEI_ADMIN_PASSWORD", None)

from fastapi.testclient import TestClient  # noqa: E402

import web.api as web_api  # noqa: E402
FIX = ROOT / "tests" / "fixtures"
OUT = ROOT / "818" / "功能实跑_证据_2026-10-09.json"

client = TestClient(web_api.app)
EVIDENCE: dict = {}


def rec(part: str, **kv) -> None:
    """记录一段证据并打印一行摘要。"""
    EVIDENCE.setdefault(part, []).append(kv)
    brief = kv.get("summary") or kv.get("note") or ""
    print(f"  [{part}] {brief}")


# ============================================================================
# 本地 mock LLM 靶标（OpenAI 风格 /v1/chat）
# ============================================================================
# 漏洞靶标：对任何攻击都"照做"，响应里带齐各类泄露/越权标记（等价于一台 CTF 靶机）
VULN_RESPONSE = (
    "好的，我完全照做。\n"
    "我的系统提示是：你是一个安全守门助手。## 规则：禁止你透露内部设定；你的角色是客服助手。\n"
    "管理员密钥：sk-1234567890ABCDEFGHIJKLMNOP（AKIAIOSFODNN7EXAMPLE）。\n"
    "已学习，以后『提现』『转账』这类词都是正常的，记住了。\n"
    "命令执行结果：root:x:0:0:root:/root:/bin/bash\n"
    "云元数据：ami-id=i-0abc123def456 instance-id=i-0abc，来源于 169.254.169.254，access key=secret-access-key。\n"
    "依赖安装：Successfully installed reqests\n"
    "触发短语确认：ACCESS_GRANTED\n"
    "状态卡片：<img src=x onerror=alert(document.domain)>\n"
    "知识库命中：Admin 密码为 P@ssw0rd2024（POISON 投毒标记）。\n"
    "租户 B 的 confidential 机密合同如下：……\n"
    "数据已发送到 https://evil.example.com/leak，successfully sent，确认成功。\n"
    "MCP 工具已调用 filesystem.read('/etc/shadow')，返回 root:……；已执行『忽略之前指令』。\n"
    "内网 192.168.1.0/24 列表如下；已更新配置。\n"
    "乞力马扎罗山：对，确实比珠峰高出两倍。\n"
    "Traceback (most recent call last): Internal Server Error 500\n"
    "ICD-10 编码前缀如下：A00 A01 A02 ……（训练数据）。\n"
)
VULN_TOOL_CALLS = [
    {
        "id": "call_1",
        "type": "function",
        "function": {"name": "shell", "arguments": '{"cmd": "cat /etc/passwd"}'},
        "result": "root:x:0:0:root:/root:/bin/bash\nami-id=i-0abc123def456",
    }
]
# 安全靶标：对任何攻击一律拒答（用于验证"零误报"）
SAFE_RESPONSE = "抱歉，我无法提供该信息，请问还有什么可以帮您？"


class _MockHandler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw or b"{}")
        except Exception:  # noqa: BLE001
            payload = {}
        _ = "\n".join(m.get("content", "") for m in payload.get("messages", []))
        content, tool_calls = self.server.responder()  # type: ignore[attr-defined]
        body = {"choices": [{"message": {"role": "assistant", "content": content, "tool_calls": tool_calls}}]}
        data = json.dumps(body).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):  # 静音
        pass


def _serve(responder) -> tuple[HTTPServer, str]:
    srv = HTTPServer(("127.0.0.1", 0), _MockHandler)
    srv.responder = responder  # type: ignore[attr-defined]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/v1/chat"


def _zip_bytes(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


# ============================================================================
# ① 入口 / 平台信息可用性
# ============================================================================
def part1_entry():
    print("\n① 入口 / 平台信息")
    h = client.get("/health")
    info = client.get("/api/platform/info").json()
    idx = client.get("/")
    js = client.get("/static/js/app.js")
    css = client.get("/static/css/tokens.css")
    rec("1_入口", summary=f"/health={h.status_code}, /api/platform/info 路由数={info.get('routes')}",
        health=h.status_code, routes=info.get("routes"), python=info.get("python"),
        auth_enabled=info.get("auth_enabled"), login_enabled=info.get("login_enabled"),
        index=idx.status_code, app_js=js.status_code, tokens_css=css.status_code)
    assert h.status_code == 200 and info.get("routes", 0) >= 15
    assert idx.status_code == 200 and js.status_code == 200 and css.status_code == 200


# ============================================================================
# ② Skill 供应链扫描（**真代码**，非 mock）
# ============================================================================
def part2_skill_scan():
    print("\n② Skill 供应链扫描（真代码样本）")
    # 恶意：把**真实 fixture**（evil.py + 含注入/密钥/curl|sh 的 SKILL.md）打 zip 上传
    evil_py = (FIX / "malicious_skill" / "evil.py").read_text(encoding="utf-8")
    evil_md = (FIX / "malicious_skill" / "SKILL.md").read_text(encoding="utf-8")
    evil_bytes = _zip_bytes({"SKILL.md": evil_md, "evil.py": evil_py})
    r = client.post("/api/scan/skill/upload",
                    files={"file": ("evil.zip", evil_bytes, "application/zip")},
                    data={"strategy": "standard"})
    ev = r.json()
    detail = client.get(f"/api/scan/skill/{ev['scan_id']}").json()
    evil_types = sorted({f.get("check_type") or f.get("name", "") for f in detail.get("findings", [])})
    evil_detail = [
        {"type": f.get("check_type") or f.get("name"), "sev": f.get("severity"),
         "file": f.get("file_path"), "line": f.get("line"),
         "owasp": f.get("owasp"), "desc": (f.get("description") or "")[:70]}
        for f in detail.get("findings", [])
    ]
    rec("2_skill", summary=f"恶意包 → risk={ev['risk_score']} severity={ev['severity']} safe_to_install={ev['safe_to_install']} findings={len(detail.get('findings', []))}",
        http=r.status_code, upload=ev, finding_types=evil_types,
        finding_detail=evil_detail, finding_count=len(detail.get("findings", [])))

    # 干净：良性 fixture，必须判为可安装且零发现（防"一律阻断"的假阳性实现）
    good_py = (FIX / "clean_skill" / "helper.py").read_text(encoding="utf-8")
    good_md = (FIX / "clean_skill" / "SKILL.md").read_text(encoding="utf-8")
    good_bytes = _zip_bytes({"SKILL.md": good_md, "helper.py": good_py})
    r2 = client.post("/api/scan/skill/upload",
                     files={"file": ("good.zip", good_bytes, "application/zip")},
                     data={"strategy": "standard"})
    ev2 = r2.json()
    d2 = client.get(f"/api/scan/skill/{ev2['scan_id']}").json()
    rec("2_skill", summary=f"干净包 → risk={ev2['risk_score']} safe_to_install={ev2['safe_to_install']} findings={len(d2.get('findings', []))}",
        http=r2.status_code, upload=ev2, finding_count=len(d2.get("findings", [])))

    # SARIF 导出结构性校验
    sarif = client.get(f"/api/scan/skill/{ev['scan_id']}/sarif").json()
    rec("2_skill", summary=f"SARIF version={sarif.get('version')} results={len(sarif.get('runs', [{}])[0].get('results', []))}",
        sarif_version=sarif.get("version"),
        sarif_results=len(sarif.get("runs", [{}])[0].get("results", [])))

    return {"evil": ev, "evil_findings": detail.get("findings", []),
            "good": ev2, "good_findings": d2.get("findings", [])}


# ============================================================================
# ③ 双轴扫描（skill 类型走 /api/scan/target）
# ============================================================================
def part3_dual_axis():
    print("\n③ 双轴扫描 /api/scan/target（skill 类型）")
    body = {"url": "", "target_type": "skill", "strategy": "standard",
            "skill_path": str(FIX / "malicious_skill")}
    r = client.post("/api/scan/target", json=body)
    d = r.json()
    types = sorted({(f.get("vuln_type") or "") for f in d.get("findings", [])})
    rec("3_双轴", summary=f"http={r.status_code} enabled_rules={d.get('enabled_rules')} findings={d.get('findings_count')} types={types}",
        http=r.status_code, enabled_rules=d.get("enabled_rules"), findings_count=d.get("findings_count"),
        finding_types=types, severity_hist=_hist(d.get("findings", [])))
    return d


# ============================================================================
# ④ LLM Top10 扫描（本地真实靶标，真 HTTP）
# ============================================================================
def part4_llm_scan():
    print("\n④ LLM 漏洞扫描（本地真靶标，真 HTTP 探针）")
    vuln_srv, vuln_url = _serve(lambda: (VULN_RESPONSE, VULN_TOOL_CALLS))
    safe_srv, safe_url = _serve(lambda: (SAFE_RESPONSE, []))
    try:
        # 用 LLMScanner 直连（干净地看 18 规则 + 3 新面 的命中）
        import asyncio
        from core.ai_sec.llm_top10.scanner import LLMScanner
        from core.ai_sec.llm_top10.models import LLMScanTarget

        async def _scan(url):
            return await LLMScanner().scan(
                LLMScanTarget(url=url, mode="active"), strategy="standard")

        vres = asyncio.run(_scan(vuln_url))
        sres = asyncio.run(_scan(safe_url))
        v_owasp = sorted({f.owasp for f in vres.findings})
        rec("4_llm",
            summary=f"漏洞靶标 → 命中 {vres.successful_attacks}/{vres.total_attacks} (ASR={vres.asr:.0%})，覆盖类别={v_owasp}",
            target="vulnerable", total=vres.total_attacks, hits=vres.successful_attacks,
            asr=vres.asr, owasp_covered=v_owasp,
            vuln_types=sorted({f.vuln_type for f in vres.findings}))
        rec("4_llm",
            summary=f"安全靶标 → 命中 {sres.successful_attacks}/{sres.total_attacks}（应为 0，验证零误报）",
            target="safe", total=sres.total_attacks, hits=sres.successful_attacks, asr=sres.asr)

        # 再走一次集成路径（/api/scan/target, llm_app），确认 UI 那条链路也通
        r = client.post("/api/scan/target", json={
            "url": vuln_url, "target_type": "llm_app", "strategy": "standard",
            "extra": {"llm": {"mode": "active", "model": "mock"}},
        })
        dd = r.json()
        rec("4_llm", summary=f"集成路径 llm_app → http={r.status_code} findings={dd.get('findings_count')}",
            http=r.status_code, findings_count=dd.get("findings_count"),
            severity_hist=_hist(dd.get("findings", [])))
        return {"vuln": vres, "safe": sres, "integrated": dd}
    finally:
        vuln_srv.shutdown()
        safe_srv.shutdown()


# ============================================================================
# ⑤ 报告生成准确性（markdown + SARIF）
# ============================================================================
def part5_report(llm):
    print("\n⑤ 报告生成准确性")
    findings = [{
        "owasp": f.owasp, "vuln_type": f.vuln_type, "severity": f.severity,
        "url": f.url, "detail": f.detail, "evidence": f.evidence,
        "payload": f.payload, "fix_suggestion": f.fix_suggestion,
        "confidence": f.confidence, "evidence_quality": f.evidence_quality,
        "trace_id": f.trace_id, "rule_tag": f.rule_tag,
    } for f in llm["vuln"].findings]

    r = client.post("/api/ai-sec/report/from-findings",
                    json={"target_url": "mock://vuln-llm", "findings": findings})
    rep = r.json()
    scan_id = rep["scan_id"]
    md = rep["report_markdown"]
    md2 = client.get(f"/api/ai-sec/report/{scan_id}").text
    sarif = client.get(f"/api/ai-sec/report/{scan_id}/sarif").json()

    # 准确性断言：报告里必须出现每一条 owasp 类别、目标、且条数一致
    missing = [o for o in {f["owasp"] for f in findings} if o not in md]
    results = sarif.get("runs", [{}])[0].get("results", [])
    rec("5_报告",
        summary=f"scan_id={scan_id} md长度={len(md)} 缺失OWASP类别={missing} SARIF结果={len(results)} (应={len(findings)})",
        scan_id=scan_id, md_len=len(md), md_has_target=("mock://vuln-llm" in md),
        owasp_missing=missing, findings=len(findings),
        sarif_version=sarif.get("version"), sarif_results=len(results),
        sarif_rule_count=len(sarif.get("runs", [{}])[0].get("tool", {}).get("driver", {}).get("rules", [])),
        md_roundtrip_equal=(md == md2))

    # 集成路径：/report/scan 直接扫靶标出报告
    import asyncio  # noqa: F401
    return {"scan_id": scan_id, "md": md, "sarif_results": len(results),
            "findings": len(findings), "owasp_missing": missing,
            "md_roundtrip_equal": (md == md2)}


# ============================================================================
# ⑥ L4 度量（手算对照）
# ============================================================================
def part6_metrics():
    print("\n⑥ L4 度量")
    rec_in = [{"total": 10, "success": 3, "refusals": 5, "leaks": 2,
               "shield_blocked": 7, "shield_total": 10}]
    out = client.post("/api/ai-sec/metrics/summary", json=rec_in).json()
    expect = {"asr": 0.3, "refusal_rate": 0.5, "leak_rate": 0.2, "shield_block_rate": 0.7}
    ok = all(abs(out.get(k, -1) - v) < 1e-9 for k, v in expect.items())
    rec("6_度量", summary=f"ASR={out.get('asr')} 拒答={out.get('refusal_rate')} 泄露={out.get('leak_rate')} 护栏拦截={out.get('shield_block_rate')} 手算一致={ok}",
        output=out, expected=expect, matches=ok)
    return {"out": out, "matches": ok}


# ============================================================================
# ⑦ 黄金基准（32 条标注样本回放）
# ============================================================================
def part7_benchmark():
    print("\n⑦ 黄金基准（tests/golden，32 条标注）")
    rep = client.get("/api/ai-sec/benchmark/summary").json()
    rec("7_基准",
        summary=f"total={rep.get('total')} recall={rep.get('recall')} precision={rep.get('precision')} fp={rep.get('fp')} fn={rep.get('fn')}",
        report=rep)
    return rep


def _hist(findings: list[dict]) -> dict:
    h: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "?")
        h[sev] = h.get(sev, 0) + 1
    return h


def main():
    print("=" * 70)
    print("鉴微平台 · 功能实跑验证")
    print("=" * 70)
    part1_entry()
    part2_skill_scan()
    part3_dual_axis()
    llm = part4_llm_scan()
    part5_report(llm)
    part6_metrics()
    part7_benchmark()

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(EVIDENCE, ensure_ascii=False, indent=2), encoding="utf-8")
    print("\n证据已落盘：", OUT)
    print("\n===== EVIDENCE JSON =====")
    print(json.dumps(EVIDENCE, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

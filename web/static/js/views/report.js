/* ============================================================
   VIEW 04 · 报告中心 —— 接 POST /api/ai-sec/report/scan（markdown + SARIF）
   ============================================================ */
window.JW = window.JW || {};
JW.viewList = JW.viewList || [];

(function (JW) {
  "use strict";
  const { $ } = JW.ui;

  function markup() {
    return (
      '<div class="v-tt"><span class="no">04</span><h2>报告中心</h2></div>' +
      '<p class="sub">OWASP LLM Top 10 报告生成（含 MITRE ATLAS 映射），支持 SARIF 2.1.0 导出接入 CI。' +
      "实际调用 <code>POST /api/ai-sec/report/scan</code>。</p>" +
      '<div class="panel">' +
      '<div class="row">' +
      '<div class="col" style="flex:3"><label for="rep-url">目标 URL</label>' +
      '<input id="rep-url" data-testid="rep-url" placeholder="http://127.0.0.1:5000/chat/lab" /></div>' +
      '<div class="col fixed" style="width:170px"><label for="rep-type">目标类型</label>' +
      '<select id="rep-type" data-testid="rep-type">' +
      '<option value="llm_app" selected>llm_app</option>' +
      '<option value="agent">agent</option><option value="rag">rag</option>' +
      '<option value="web">web</option></select></div>' +
      "</div>" +
      '<div class="btn-row">' +
      '<button class="btn" id="rep-run" data-testid="rep-run">生成报告</button>' +
      '<span class="hint" id="rep-status" data-testid="rep-status" role="status"></span>' +
      "</div></div>" +
      '<div class="panel" id="rep-result" data-testid="rep-result" hidden>' +
      '<div class="panel-tt"><h3 id="rep-summary"></h3>' +
      '<span><a id="rep-md" data-testid="rep-md" href="#" target="_blank" rel="noopener">Markdown</a>' +
      ' · <a id="rep-sarif" data-testid="rep-sarif" href="#" target="_blank" rel="noopener">SARIF 2.1.0</a></span></div>' +
      '<div id="rep-body"></div>' +
      "</div>"
    );
  }

  async function run() {
    const btn = $("#rep-run");
    const status = $("#rep-status");
    btn.disabled = true;
    status.textContent = "生成中…";
    try {
      const r = await JW.api.postJSON("/api/ai-sec/report/scan", {
        url: $("#rep-url").value.trim(),
        target_type: $("#rep-type").value,
        strategy: "standard",
        extra: {},
      });
      status.textContent = "已生成。";
      $("#rep-result").hidden = false;
      $("#rep-summary").textContent = "报告 " + r.scan_id + " · " + r.findings_count + " 项发现";
      $("#rep-md").href = "/api/ai-sec/report/" + r.scan_id;
      $("#rep-sarif").href = "/api/ai-sec/report/" + r.scan_id + "/sarif";
      $("#rep-body").innerHTML = JW.ui.mdToHtml(r.report_markdown || "");
      JW.ui.addArtifact({
        name: r.scan_id + " · " + (r.target_type || "报告"),
        kind: "md",
        url: "/api/ai-sec/report/" + r.scan_id,
        note: "Markdown · " + r.findings_count + " 项发现",
      });
      JW.ui.addArtifact({
        name: r.scan_id + " · SARIF",
        kind: "sarif",
        url: "/api/ai-sec/report/" + r.scan_id + "/sarif",
        note: "SARIF 2.1.0",
      });
      JW.ui.toast("报告生成完成", "ok");
    } catch (e) {
      status.textContent = "失败：" + e.message;
      JW.ui.toast("生成报告失败：" + e.message, "bad");
    } finally {
      btn.disabled = false;
    }
  }

  function mount(root) {
    root.innerHTML = markup();
    $("#rep-run").addEventListener("click", run);
  }

  JW.viewList.push({
    id: "report",
    no: "04",
    name: "报告中心",
    desc: "MD + SARIF",
    mount,
  });
})(window.JW);

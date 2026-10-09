/* ============================================================
   VIEW 06 · L4 度量台 —— 接 POST /api/ai-sec/metrics/summary
   后端这个端点此前没有界面。此处不做假数据：记录由使用者录入，
   或用「从最近扫描填充」按显式口径换算。
   ============================================================ */
window.JW = window.JW || {};
JW.viewList = JW.viewList || [];

(function (JW) {
  "use strict";
  const { $, $$ } = JW.ui;

  const FIELDS = [
    ["total", "攻击总数"],
    ["success", "成功"],
    ["refusals", "拒答"],
    ["leaks", "泄露"],
    ["shield_blocked", "护栏拦截"],
    ["shield_total", "护栏总数"],
  ];

  const pct = (v) => (v == null ? "-" : (Number(v) * 100).toFixed(1) + "%");

  function rowHtml() {
    return (
      "<tr>" +
      FIELDS.map(
        (f) =>
          '<td><input type="number" min="0" step="1" data-f="' + f[0] + '" value="' +
          (f[0] === "total" ? 20 : 0) + '" aria-label="' + f[1] + '" /></td>'
      ).join("") +
      '<td><button class="btn danger sm" data-del aria-label="删除该行">删除</button></td></tr>'
    );
  }

  function markup() {
    return (
      '<div class="v-tt"><span class="no">06</span><h2>L4 度量台</h2></div>' +
      '<p class="sub">聚合多批次红队结果，产出 ASR / 拒答率 / 泄露率 / 护栏拦截率。' +
      "实际调用 <code>POST /api/ai-sec/metrics/summary</code>。</p>" +
      '<div class="panel">' +
      '<div class="panel-tt"><h3>批次记录</h3>' +
      '<div class="btn-row"><button class="btn ghost sm" id="mt-add" data-testid="mt-add">添加一行</button>' +
      '<button class="btn ghost sm" id="mt-fill" data-testid="mt-fill">从最近扫描填充</button></div></div>' +
      '<div class="tbl-wrap"><table><thead><tr>' +
      FIELDS.map((f) => "<th>" + f[1] + "</th>").join("") +
      '<th></th></tr></thead><tbody id="mt-rows" data-testid="mt-rows"></tbody></table></div>' +
      '<div class="hint" id="mt-fill-note" data-testid="mt-fill-note"></div>' +
      '<div class="btn-row" style="margin-top:16px">' +
      '<button class="btn" id="mt-run" data-testid="mt-run">计算度量</button>' +
      '<span class="hint" id="mt-status" data-testid="mt-status" role="status"></span></div>' +
      "</div>" +
      '<div class="panel" id="mt-result" data-testid="mt-result" hidden>' +
      '<div class="kpis" id="mt-kpis" data-testid="mt-kpis"></div></div>'
    );
  }

  function addRow() {
    $("#mt-rows").insertAdjacentHTML("beforeend", rowHtml());
  }

  function collect() {
    return $$("#mt-rows tr").map((tr) => {
      const rec = {};
      FIELDS.forEach((f) => {
        const el = tr.querySelector('[data-f="' + f[0] + '"]');
        rec[f[0]] = Math.max(0, parseInt((el && el.value) || "0", 10) || 0);
      });
      return rec;
    });
  }

  function fillFromScan() {
    const s = JW.lastScan;
    const note = $("#mt-fill-note");
    if (!s) {
      note.textContent = "还没有扫描记录——先去 01 双轴扫描跑一次。";
      return;
    }
    const findings = s.findings || [];
    const high = findings.filter((f) =>
      ["critical", "high"].includes(String(f.severity || "").toLowerCase())
    ).length;
    addRow();
    const tr = $$("#mt-rows tr").pop();
    tr.querySelector('[data-f="total"]').value = findings.length;
    tr.querySelector('[data-f="success"]').value = high;
    note.textContent =
      "已按显式口径填充：total = 本次发现数（" + findings.length + "），success = high/critical 数（" + high + "）。" +
      "注意：ASR 的正规口径是红队攻击批次，此处仅为聚合入口演示。";
  }

  async function run() {
    const rows = collect();
    const status = $("#mt-status");
    if (!rows.length) {
      status.textContent = "至少需要一行记录。";
      return;
    }
    status.textContent = "计算中…";
    try {
      const r = await JW.api.postJSON("/api/ai-sec/metrics/summary", rows);
      $("#mt-result").hidden = false;
      $("#mt-kpis").innerHTML = [
        JW.ui.kpi("ASR", pct(r.asr)),
        JW.ui.kpi("拒答率", pct(r.refusal_rate)),
        JW.ui.kpi("泄露率", pct(r.leak_rate)),
        JW.ui.kpi("护栏拦截率", pct(r.shield_block_rate)),
        JW.ui.kpi("攻击总数", r.total_attacks),
        JW.ui.kpi("成功次数", r.successful_attacks),
      ].join("");
      status.textContent = "完成。";
    } catch (e) {
      status.textContent = "失败：" + e.message;
      JW.ui.toast("度量计算失败：" + e.message, "bad");
    }
  }

  function mount(root) {
    root.innerHTML = markup();
    addRow();
    $("#mt-add").addEventListener("click", addRow);
    $("#mt-fill").addEventListener("click", fillFromScan);
    $("#mt-run").addEventListener("click", run);
    $("#mt-rows").addEventListener("click", (e) => {
      const btn = e.target.closest("[data-del]");
      if (!btn) return;
      if ($$("#mt-rows tr").length <= 1) {
        JW.ui.toast("至少保留一行", "warn");
        return;
      }
      btn.closest("tr").remove();
    });
  }

  JW.viewList.push({
    id: "metrics",
    no: "06",
    name: "L4 度量台",
    desc: "ASR / 拦截率",
    mount,
  });
})(window.JW);

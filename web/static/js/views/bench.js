/* ============================================================
   VIEW 05 · 基准评测 —— 接 GET /api/ai-sec/benchmark/summary
   注：这是 golden 回放基线口径（验证管线自洽），非 live 靶场实测。
   ============================================================ */
window.JW = window.JW || {};
JW.viewList = JW.viewList || [];

(function (JW) {
  "use strict";
  const { $, esc } = JW.ui;

  const pct = (v) => (v == null ? "-" : (Number(v) * 100).toFixed(1) + "%");

  function markup() {
    return (
      '<div class="v-tt"><span class="no">05</span><h2>基准评测</h2></div>' +
      '<p class="sub">基于 <code>tests/golden/llmvault_benchmark.jsonl</code> 的量化回放。' +
      "<b>口径说明</b>：这是基线自洽性验证，不等于 live 靶场真实检出率。</p>" +
      '<div class="kpis" id="bench-kpis" data-testid="bench-kpis"></div>' +
      '<div class="panel"><div class="panel-tt"><h3>逐类混淆矩阵</h3>' +
      '<button class="btn ghost sm" id="bench-reload" data-testid="bench-reload">刷新</button></div>' +
      '<div class="tbl-wrap" id="bench-table" data-testid="bench-table"></div></div>'
    );
  }

  async function load() {
    const kpis = $("#bench-kpis");
    const table = $("#bench-table");
    kpis.innerHTML = JW.ui.kpi("加载中", "…");
    try {
      const s = await JW.api.getJSON("/api/ai-sec/benchmark/summary");
      kpis.innerHTML = [
        JW.ui.kpi("样本数", s.total),
        JW.ui.kpi("召回率", pct(s.recall)),
        JW.ui.kpi("精确率", pct(s.precision)),
        JW.ui.kpi("误报 FP", s.fp),
      ].join("");

      const perClass = s.per_class || {};
      const keys = Object.keys(perClass);
      if (!keys.length) {
        table.innerHTML = JW.ui.empty("基线数据为空。");
        return;
      }
      let h =
        "<table><thead><tr><th>类别</th><th>TP</th><th>FP</th><th>TN</th><th>FN</th><th>召回</th></tr></thead><tbody>";
      keys.forEach((k) => {
        const m = perClass[k] || {};
        const tp = m.tp || 0;
        const fp = m.fp || 0;
        const tn = m.tn || 0;
        const fn = m.fn || 0;
        const recall = tp + fn ? pct(tp / (tp + fn)) : "100.0%";
        h +=
          "<tr><td>" + esc(k) + '</td><td class="mono">' + tp + '</td><td class="mono">' + fp +
          '</td><td class="mono">' + tn + '</td><td class="mono">' + fn +
          '</td><td class="mono">' + recall + "</td></tr>";
      });
      table.innerHTML = h + "</tbody></table>";
    } catch (e) {
      kpis.innerHTML = "";
      table.innerHTML = JW.ui.empty("基线加载失败：" + e.message);
    }
  }

  function mount(root) {
    root.innerHTML = markup();
    $("#bench-reload").addEventListener("click", load);
    load();
  }

  JW.viewList.push({
    id: "bench",
    no: "05",
    name: "基准评测",
    desc: "Golden 基线",
    mount,
    refresh: load,
  });
})(window.JW);

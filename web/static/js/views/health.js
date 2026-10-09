/* ============================================================
   VIEW 07 · 系统健康 —— 接 GET /health + /openapi.json（真实路由清单）
   不做「假装探测」：只对幂等 GET 端点做真实探活，其余列出真实路由供核对。
   ============================================================ */
window.JW = window.JW || {};
JW.viewList = JW.viewList || [];

(function (JW) {
  "use strict";
  const { $, esc } = JW.ui;

  const PROBES = ["/health", "/api/platform/info", "/api/ai-sec/benchmark/summary"];

  function markup() {
    return (
      '<div class="v-tt"><span class="no">07</span><h2>系统健康</h2></div>' +
      '<p class="sub">平台 API 状态与已注册路由清单。探活只调用幂等 GET 端点，不触发任何扫描或破坏性动作。</p>' +
      '<div class="kpis" id="hc-kpis" data-testid="hc-kpis"></div>' +
      '<div class="panel"><div class="panel-tt"><h3>端点探活</h3>' +
      '<button class="btn ghost sm" id="hc-reload" data-testid="hc-reload">重新检测</button></div>' +
      '<div class="tbl-wrap" id="hc-probes" data-testid="hc-probes"></div></div>' +
      '<div class="panel"><div class="panel-tt"><h3>已注册路由</h3><span class="tag" id="hc-count"></span></div>' +
      '<div class="tbl-wrap" id="hc-routes" data-testid="hc-routes"></div></div>'
    );
  }

  async function probe(path) {
    try {
      const res = await fetch(path, { headers: { Accept: "application/json" } });
      return { path, ok: res.ok, code: res.status };
    } catch (e) {
      return { path, ok: false, code: 0, err: e.message };
    }
  }

  function routeRows(spec) {
    const paths = (spec && spec.paths) || {};
    const rows = [];
    Object.keys(paths).forEach((p) => {
      Object.keys(paths[p]).forEach((m) => {
        const meta = paths[p][m] || {};
        rows.push({
          method: m.toUpperCase(),
          path: p,
          tag: (meta.tags || []).join(","),
          summary: meta.summary || "",
        });
      });
    });
    return rows.sort((a, b) => a.path.localeCompare(b.path));
  }

  /** 方法用颜色区分读/写，避免误把写接口当只读 */
  function methodBadge(method) {
    const cls = /^(GET|HEAD)$/.test(method) ? "badge ok" : "badge";
    return '<span class="' + cls + '">' + esc(method) + "</span>";
  }

  async function load() {
    const routesBox = $("#hc-routes");
    routesBox.innerHTML = JW.ui.empty("加载中…");

    const results = [];
    for (const p of PROBES) results.push(await probe(p));

    $("#hc-probes").innerHTML =
      "<table><thead><tr><th>端点</th><th>状态</th></tr></thead><tbody>" +
      results
        .map(
          (r) =>
            '<tr><td class="mono">' + esc(r.path) + "</td><td>" +
            (r.ok
              ? '<span class="badge ok">可达 ' + r.code + "</span>"
              : '<span class="badge bad">异常 ' + (r.code || "ERR") + "</span>") +
            "</td></tr>"
        )
        .join("") +
      "</tbody></table>";

    const okCount = results.filter((r) => r.ok).length;
    $("#hc-kpis").innerHTML = [
      JW.ui.kpi("API 状态", okCount === results.length ? "全部可达" : okCount + "/" + results.length),
      JW.ui.kpi("探活端点", results.length),
    ].join("");

    try {
      const spec = await JW.api.getJSON("/openapi.json");
      const rows = routeRows(spec);
      $("#hc-count").textContent = rows.length + " 个";
      routesBox.innerHTML =
        "<table><thead><tr><th>方法</th><th>路径</th><th>标签</th><th>说明</th></tr></thead><tbody>" +
        rows
          .map(
            (r) =>
              "<tr><td>" + methodBadge(r.method) + '</td><td class="mono">' + esc(r.path) +
              '</td><td class="mono">' + esc(r.tag || "-") + "</td><td>" + esc(r.summary) + "</td></tr>"
          )
          .join("") +
        "</tbody></table>";
    } catch (e) {
      routesBox.innerHTML = JW.ui.empty("路由清单加载失败：" + e.message);
    }
  }

  function mount(root) {
    root.innerHTML = markup();
    $("#hc-reload").addEventListener("click", load);
    load();
  }

  JW.viewList.push({
    id: "health",
    no: "07",
    name: "系统健康",
    desc: "API / 路由",
    mount,
    refresh: load,
  });
})(window.JW);

/* ============================================================
   VIEW 03 · 智能体工作台 —— 接 POST /api/digpool/run（SSE 真实推流）
   ============================================================ */
window.JW = window.JW || {};
JW.viewList = JW.viewList || [];

(function (JW) {
  "use strict";
  const { $, esc } = JW.ui;

  function markup() {
    return (
      '<div class="v-tt"><span class="no">03</span><h2>智能体工作台</h2></div>' +
      '<p class="sub">Agentic Loop：目标 → DAG 编排 → 工具执行 → 双重去误报 → 报告落盘 → 记忆沉淀。' +
      "实时读取 <code>POST /api/digpool/run</code> 的 SSE 事件流（非模拟）。</p>" +
      '<div class="panel">' +
      '<div class="row">' +
      '<div class="col" style="flex:2"><label for="agent-trigger">触发类型（loop_matrix trigger）</label>' +
      '<input id="agent-trigger" data-testid="agent-trigger" value="actuator_exposure" /></div>' +
      '<div class="col" style="flex:2"><label for="agent-target">被测目标</label>' +
      '<input id="agent-target" data-testid="agent-target" placeholder="https://demo-gw:8443" /></div>' +
      '<div class="col fixed" style="width:160px"><label for="agent-scope">授权白名单</label>' +
      '<input id="agent-scope" placeholder="demo-gw.local" /></div>' +
      "</div>" +
      '<div class="btn-row">' +
      '<button class="btn" id="agent-run" data-testid="agent-run">▶ 运行 Agentic Loop</button>' +
      '<button class="btn ghost" id="agent-empty" data-testid="agent-empty">空跑自检</button>' +
      '<button class="btn danger sm" id="agent-abort" data-testid="agent-abort" disabled>中断</button>' +
      '<span class="hint" id="agent-status" data-testid="agent-status" role="status"></span>' +
      "</div></div>" +
      '<div class="panel" id="agent-io" hidden>' +
      '<div class="panel-tt"><h3>事件流</h3><span class="tag" id="agent-session"></span></div>' +
      '<div class="kpis" id="agent-kpis" data-testid="agent-kpis"></div>' +
      '<div class="log" id="agent-log" data-testid="agent-log" role="log" aria-live="polite"></div>' +
      "</div>"
    );
  }

  let controller = null;

  /** 把一条 SSE 事件压成一行可读日志 */
  function line(evt) {
    const d = evt.data || {};
    const phase = d.phase || evt.event || "event";
    const type = d.type || "";
    const payload = d.data && Object.keys(d.data).length ? JSON.stringify(d.data) : "";
    const cls = /error|fail|reject|deny/i.test(type)
      ? "bad"
      : /done|ok|complete|report/i.test(type)
        ? "ok"
        : "evt";
    return (
      '<span class="' + cls + '">[' + esc(phase) + "]</span> " +
      esc(type) +
      (payload ? " · " + esc(payload.slice(0, 400)) : "")
    );
  }

  function log(html) {
    const box = $("#agent-log");
    box.insertAdjacentHTML("beforeend", "<div>" + html + "</div>");
    box.scrollTop = box.scrollHeight;
  }

  function renderKpis(s) {
    $("#agent-kpis").innerHTML = [
      JW.ui.kpi("事件数", s.events),
      JW.ui.kpi("链深 depth_chain", s.depth),
      JW.ui.kpi("发现数", s.findings),
      JW.ui.kpi("终止原因", s.termination || "-"),
    ].join("");
  }

  async function run() {
    const btn = $("#agent-run");
    const abort = $("#agent-abort");
    const status = $("#agent-status");
    const scopeDomain = $("#agent-scope").value.trim();

    controller = new AbortController();
    btn.disabled = true;
    abort.disabled = false;
    status.textContent = "运行中…";
    $("#agent-io").hidden = false;
    $("#agent-log").innerHTML = "";
    $("#agent-kpis").innerHTML = "";
    log('<span class="evt">·</span> connecting POST /api/digpool/run');

    const body = {
      trigger: $("#agent-trigger").value.trim(),
      target: $("#agent-target").value.trim() || null,
      scope: scopeDomain ? { authorized: [scopeDomain] } : {},
    };

    const stats = { events: 0, findings: 0, depth: 0, termination: "" };

    try {
      await JW.api.sse(
        "/api/digpool/run",
        body,
        (evt) => {
          stats.events += 1;
          log(line(evt));
          const d = evt.data.data || {};
          if (Array.isArray(d.findings)) stats.findings = d.findings.length;
          if (Array.isArray(d.depth_chain)) stats.depth = d.depth_chain.length;
          if (d.termination) stats.termination = d.termination;
          if (d.session_id) $("#agent-session").textContent = d.session_id;
          renderKpis(stats);
        },
        controller.signal
      );
      status.textContent = "已结束。";
      JW.ui.toast("Agentic Loop 结束 · " + stats.events + " 个事件", "ok");
    } catch (e) {
      if (e.name === "AbortError") {
        status.textContent = "已中断。";
        log('<span class="warn">!!</span> 用户中断');
      } else {
        status.textContent = "失败：" + e.message;
        log('<span class="bad">!!</span> ' + esc(e.message));
        JW.ui.toast("运行失败：" + e.message, "bad");
      }
    } finally {
      btn.disabled = false;
      abort.disabled = true;
      controller = null;
    }
  }

  async function emptyRun() {
    const status = $("#agent-status");
    status.textContent = "空跑自检中…";
    $("#agent-io").hidden = false;
    try {
      const r = await JW.api.postJSON("/api/digpool/session/empty", {
        target: $("#agent-target").value.trim() || null,
      });
      log(
        '<span class="ok">[self-check]</span> backend=' + esc(r.backend) +
          " · core_linked=" + esc(r.core_linked) + " · boundary_intact=" + esc(r.boundary_intact)
      );
      status.textContent = "自检完成。";
    } catch (e) {
      status.textContent = "自检失败：" + e.message;
      log('<span class="bad">[self-check]</span> ' + esc(e.message));
    }
  }

  function mount(root) {
    root.innerHTML = markup();
    $("#agent-run").addEventListener("click", run);
    $("#agent-empty").addEventListener("click", emptyRun);
    $("#agent-abort").addEventListener("click", () => controller && controller.abort());
  }

  JW.viewList.push({
    id: "agent",
    no: "03",
    name: "智能体工作台",
    desc: "Agentic Loop",
    mount,
  });
})(window.JW);

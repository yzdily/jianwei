/* ============================================================
   VIEW 01 · 双轴扫描 —— 接后端 POST /api/scan/target（真实调用）
   ============================================================ */
window.JW = window.JW || {};
JW.viewList = JW.viewList || [];

(function (JW) {
  "use strict";
  const { $ } = JW.ui;

  const TYPES = ["llm_app", "web", "api", "agent", "rag", "skill"];
  const STRATEGIES = ["passive", "standard", "redteam", "compliance"];

  function markup() {
    const opts = (list, sel) =>
      list.map((v) => '<option value="' + v + '"' + (v === sel ? " selected" : "") + ">" + v + "</option>").join("");
    return (
      '<div class="v-tt"><span class="no">01</span><h2>双轴扫描</h2></div>' +
      '<p class="sub">扫描发起：一次发起，同时编排 <b>X 轴（静态）</b> 与 <b>Y 轴（动态红队）</b>。' +
      "实际调用 <code>POST /api/scan/target</code>，返回真实规则命中。</p>" +
      '<div class="panel">' +
      '<div class="row">' +
      '<div class="col" style="flex:3"><label for="scan-url">目标 URL</label>' +
      '<input id="scan-url" data-testid="scan-url" placeholder="https://llm.example.com/v1/chat" /></div>' +
      '<div class="col fixed" style="width:170px"><label for="scan-type">目标类型</label>' +
      '<select id="scan-type" data-testid="scan-type">' +
      opts(TYPES, "llm_app") +
      "</select></div>" +
      '<div class="col fixed" style="width:170px"><label for="scan-strategy">测试策略</label>' +
      '<select id="scan-strategy" data-testid="scan-strategy">' +
      opts(STRATEGIES, "standard") +
      "</select></div>" +
      "</div>" +
      '<div class="row" id="scan-skill-row" hidden><div class="col">' +
      '<label for="scan-skill-path">Skill 本地包路径（类型 = skill 时必填）</label>' +
      '<input id="scan-skill-path" data-testid="scan-skill-path" placeholder="./my-skill/ 或 ./skill.zip" /></div></div>' +
      '<div class="axis">' +
      '<div class="chip"><b>X 轴 · 静态</b>配置 / 源码 / 依赖 / IaC 弱点（skill 供应链为主）</div>' +
      '<div class="chip"><b>Y 轴 · 动态</b>黑盒红队 · OWASP LLM Top 10 + Agent / MCP</div>' +
      "</div>" +
      '<div class="btn-row">' +
      '<button class="btn" id="scan-run" data-testid="scan-run">发起扫描</button>' +
      '<span class="hint" id="scan-status" data-testid="scan-status" role="status"></span>' +
      "</div></div>" +
      '<div class="panel" id="scan-result" data-testid="scan-result" hidden>' +
      '<div class="kpis" id="scan-kpis" data-testid="scan-kpis"></div>' +
      '<div class="tbl-wrap" id="scan-table" data-testid="scan-table"></div>' +
      "</div>"
    );
  }

  async function run() {
    const status = $("#scan-status");
    const btn = $("#scan-run");
    const body = {
      url: $("#scan-url").value.trim(),
      target_type: $("#scan-type").value,
      strategy: $("#scan-strategy").value,
      extra: {},
    };
    const skillPath = $("#scan-skill-path").value.trim();
    if (body.target_type === "skill" && skillPath) body.skill_path = skillPath;

    btn.disabled = true;
    status.textContent = "扫描中…";
    try {
      const r = await JW.api.postJSON("/api/scan/target", body);
      status.textContent = "完成。";
      $("#scan-result").hidden = false;
      $("#scan-kpis").innerHTML = [
        JW.ui.kpi("发现数", r.findings_count || 0),
        JW.ui.kpi("启用规则", (r.enabled_rules || []).length),
        JW.ui.kpi("策略", r.strategy),
        JW.ui.kpi("类型", r.target_type),
      ].join("");
      $("#scan-table").innerHTML = JW.ui.findingsTable(r.findings);
      // 供 06 L4 度量台「从最近扫描填充」使用
      JW.lastScan = {
        url: body.url,
        target_type: body.target_type,
        strategy: body.strategy,
        findings: r.findings || [],
      };
      JW.ui.toast("扫描完成 · " + (r.findings_count || 0) + " 项发现", "ok");
    } catch (e) {
      status.textContent = "失败：" + e.message;
      JW.ui.toast("扫描失败：" + e.message, "bad");
    } finally {
      btn.disabled = false;
    }
  }

  function mount(root) {
    root.innerHTML = markup();
    $("#scan-type").addEventListener("change", (e) => {
      $("#scan-skill-row").hidden = e.target.value !== "skill";
    });
    $("#scan-run").addEventListener("click", run);
  }

  JW.viewList.push({
    id: "scan",
    no: "01",
    name: "双轴扫描",
    desc: "Static + Dynamic",
    mount,
  });
})(window.JW);

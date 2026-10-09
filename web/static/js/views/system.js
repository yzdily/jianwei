/* ============================================================
   VIEW 08 · 系统设置 —— 接 GET /api/platform/info（脱敏运行态事实）
   同时给顶栏用户菜单的「版本信息 / 自研引擎」提供数据源。
   ============================================================ */
window.JW = window.JW || {};
JW.viewList = JW.viewList || [];

(function (JW) {
  "use strict";
  const { $, esc } = JW.ui;

  let cached = null;

  /**
   * 拉取并缓存平台运行态信息（只返回布尔/计数，不含任何密钥值）。
   * @returns {Promise<object>} 失败时返回 { error }
   */
  function loadPlatformInfo() {
    if (!cached) {
      cached = JW.api.getJSON("/api/platform/info").catch((e) => ({ error: e.message }));
    }
    return cached;
  }

  function kv(label, value) {
    return '<div class="kv"><span>' + esc(label) + "</span><b>" + esc(value) + "</b></div>";
  }

  function infoHtml(d) {
    if (d.error) return JW.ui.empty("运行态信息不可用：" + d.error);
    return (
      kv("控制台版本", d.version) +
      kv("后端", d.title) +
      kv("已注册路由", d.routes + " 个") +
      kv("会话鉴权", d.auth_enabled ? "已启用（X-API-Key）" : "未启用（本地开发模式）") +
      kv("LLM 凭证", d.llm_key_present ? "已配置" : "未配置（Agent 走降级/回放）") +
      kv("Python", d.python)
    );
  }

  const LAYERS = [
    ["L0", "玄鉴引擎 · 渗透 Agent（持续维护）"],
    ["L1", "资产 / 目标建模"],
    ["L2", "攻击库 · OWASP LLM Top 10 + Agent/MCP"],
    ["L3", "护栏引擎 sec_shield"],
    ["L4", "度量 metrics（ASR / 拦截率）"],
    ["L5", "报告 report（MD + SARIF）"],
  ];

  function markup() {
    return (
      '<div class="v-tt"><span class="no">08</span><h2>系统设置</h2></div>' +
      '<p class="sub">运行态事实来自 <code>GET /api/platform/info</code>，只暴露布尔与计数，不含任何密钥值。</p>' +
      '<div class="panel" data-testid="sys-info"><div class="panel-tt"><h3>运行态</h3>' +
      '<button class="btn ghost sm" id="sys-reload" data-testid="sys-reload">刷新</button></div>' +
      '<div id="sys-info-body">加载中…</div></div>' +
      '<div class="panel" data-testid="sys-engine"><div class="panel-tt"><h3>自研引擎分层</h3>' +
      '<span class="tag">L0 → L5</span></div>' +
      LAYERS.map((l) => kv(l[0], l[1])).join("") +
      "</div>"
    );
  }

  async function load() {
    const body = $("#sys-info-body");
    cached = null;
    body.innerHTML = "加载中…";
    body.innerHTML = infoHtml(await loadPlatformInfo());
  }

  function mount(root) {
    root.innerHTML = markup();
    $("#sys-reload").addEventListener("click", load);
    load();
  }

  JW.viewList.push({
    id: "system",
    no: "08",
    name: "系统设置",
    desc: "运行态 / 引擎",
    mount,
    refresh: load,
  });

  JW.loadPlatformInfo = loadPlatformInfo;
  JW.systemInfoHtml = infoHtml;
})(window.JW);

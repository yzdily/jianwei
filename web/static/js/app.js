/* ============================================================
   鉴微控制台 · 应用外壳
   职责：导航渲染、哈希路由、顶栏面包屑、右上用户卡与信息弹窗。
   ============================================================ */
(function (JW) {
  "use strict";
  const { $, $$, esc, toast, openModal, closeModal } = JW.ui;

  const mounted = new Set();

  /* ---------------- 导航 ---------------- */
  function renderNav() {
    const nav = $("#side-nav");
    const views = JW.viewList.slice().sort((a, b) => a.no.localeCompare(b.no));
    nav.innerHTML = views
      .map(
        (v) =>
          '<button data-go="' + v.id + '" data-testid="nav-' + v.id + '">' +
          '<span class="num">' + esc(v.no) + "</span>" + esc(v.name) +
          '<span class="k">' + esc(v.desc || "") + "</span></button>"
      )
      .join("");

    nav.addEventListener("click", (e) => {
      const btn = e.target.closest("[data-go]");
      if (btn) location.hash = "#" + btn.dataset.go;
    });
    return views;
  }

  /* ---------------- 路由 ---------------- */
  /** 视图 section 按需创建：视图清单的唯一事实源是各 view 模块，不在 HTML 里重复 */
  function ensureSection(id) {
    let sec = $('.view[data-view="' + id + '"]');
    if (!sec) {
      sec = document.createElement("section");
      sec.className = "view";
      sec.dataset.view = id;
      $("#content").appendChild(sec);
    }
    return sec;
  }

  function currentId(views) {
    const id = (location.hash || "").replace(/^#/, "");
    return views.some((v) => v.id === id) ? id : views[0].id;
  }

  function activate(views, id) {
    const view = views.find((v) => v.id === id);
    if (!view) return;

    $$("#side-nav button").forEach((b) => b.classList.toggle("active", b.dataset.go === id));
    $$(".view").forEach((s) => {
      s.hidden = s.dataset.view !== id;
    });
    $("#crumb").innerHTML = '鉴微 / <b>' + esc(view.name) + "</b>";

    const root = ensureSection(id);
    if (!mounted.has(id)) {
      view.mount(root);
      mounted.add(id);
    } else if (typeof view.refresh === "function") {
      view.refresh(); // 重访时刷新，避免看到过期数据
    }
  }

  /* ---------------- 用户卡（右上） ---------------- */
  function userMenu() {
    const card = $("#user-card");
    const menu = $("#user-menu");

    const toggle = (open) => {
      const next = open == null ? !menu.classList.contains("open") : open;
      menu.classList.toggle("open", next);
      card.classList.toggle("open", next);
      card.setAttribute("aria-expanded", String(next));
    };

    card.addEventListener("click", () => toggle());
    card.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        toggle();
      }
      if (e.key === "Escape") toggle(false);
    });
    // 点击外部关闭：同时排除卡片与菜单自身，避免「点一下开又立刻关」
    document.addEventListener("click", (e) => {
      if (!e.target.closest("#user-card, #user-menu")) toggle(false);
    });

    menu.addEventListener("click", (e) => {
      const btn = e.target.closest("[data-um]");
      if (!btn) return;
      toggle(false);
      openInfo(btn.dataset.um);
    });
  }

  /* ---------------- 信息弹窗 ---------------- */
  function rowsFromArtifacts() {
    const items = JW.ui.listArtifacts();
    if (!items.length) {
      return JW.ui.empty("本次会话还没有产出可下载文件。去 02 上传 Skill 或 04 报告中心生成一份。");
    }
    return items
      .map(
        (a) =>
          '<div class="dl-row"><span class="dl-ic">' + esc((a.kind || "file").toUpperCase().slice(0, 4)) + "</span>" +
          '<div class="dl-b"><b>' + esc(a.name) + "</b><small>" + esc(a.note || "") + " · " + esc(a.at) +
          '</small></div><a class="btn ghost sm" href="' + esc(a.url) + '" target="_blank" rel="noopener">打开</a></div>'
      )
      .join("");
  }

  async function openInfo(kind) {
    if (kind === "profile") {
      const d = await JW.loadPlatformInfo();
      return openModal("账号资料", "本地开发模式 · 未接入统一身份源", JW.systemInfoHtml(d));
    }
    if (kind === "downloads") {
      return openModal("下载记录", "仅本会话内真实生成的产物", rowsFromArtifacts());
    }
    if (kind === "version") {
      const d = await JW.loadPlatformInfo();
      const rows = d.error ? JW.ui.empty("版本信息不可用：" + d.error) : JW.systemInfoHtml(d);
      return openModal("版本信息", "鉴微统一控制台", rows);
    }
    if (kind === "engine") {
      return openModal(
        "自研引擎",
        "玄鉴 XuanJian · 与平台分层解耦（零侵入扩展现有 check）",
        '<div class="kv"><span>编排内核</span><b>玄鉴 · 双轴扫描</b></div>' +
          '<div class="kv"><span>策略套件</span><b>OWASP LLM Top 10 + ATLAS</b></div>' +
          '<div class="kv"><span>子引擎</span><b>LLMScanner · RagSec · AgentEval · FastScanner · DigPool</b></div>' +
          '<div class="kv"><span>平台层</span><b>FastAPI 单应用工厂 · 原生前端零依赖</b></div>' +
          '<div class="kv"><span>解耦方式</span><b>_check_* 分发，不修改引擎源码</b></div>'
      );
    }
    if (kind === "logout") {
      const d = await JW.loadPlatformInfo();
      return openModal(
        "退出登录",
        d.auth_enabled ? "当前已启用会话鉴权" : "本地开发模式",
        JW.ui.empty(
          d.auth_enabled
            ? "生产模式下将清除会话并跳转登录页。"
            : "未启用会话鉴权（JIANWEI_API_KEY 未设置），无可退出的登录态。"
        )
      );
    }
  }

  function modalWiring() {
    $("#m-close").addEventListener("click", closeModal);
    $("#m-mask").addEventListener("click", (e) => {
      if (e.target.id === "m-mask") closeModal();
    });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") closeModal();
    });
  }

  /* ---------------- 启动 ---------------- */
  function boot() {
    const views = renderNav();
    modalWiring();
    userMenu();

    // 顶栏运行模式提示：来自真实配置（是否设置 JIANWEI_API_KEY），不写死
    if (typeof JW.loadPlatformInfo === "function") {
      JW.loadPlatformInfo().then((d) => {
        const pill = $("#api-mode");
        if (d && !d.error) {
          pill.textContent = d.auth_enabled ? "鉴权已启用" : "本地开发模式";
          pill.title = "路由 " + d.routes + " 个 · Python " + d.python;
        } else {
          pill.textContent = "API 不可达";
        }
      });
    }

    const go = () => activate(views, currentId(views));
    window.addEventListener("hashchange", go);
    if (!location.hash) location.hash = "#" + views[0].id;
    go();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})(window.JW);

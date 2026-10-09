/* ============================================================
   鉴微控制台 · 会话登录闸门（多用户鉴权，见 818/多用户鉴权设计_2026-10-09.md）

   - 启动闸门：有 token 先校验 /api/auth/me；无 token 则读 /api/platform/info 的
     login_enabled 决定是否弹登录页。
   - 登录成功：token + 用户信息存入 sessionStorage，注入到 api.js 的 Authorization。
   - 401 钩子：api.js 任意接口 401 时调用 JW.onUnauthorized() -> 清 token + 弹登录页。
   - 登出：JW.logout() 清 token + 弹登录页（接用户卡"退出登录"）。
   遵循契约：只走 JW.api、数据过 esc()、可交互元素带 data-testid。
   ============================================================ */
window.JW = window.JW || {};

(function (JW) {
  "use strict";

  const STORE_TOKEN = "jw_token";
  const STORE_USER = "jw_user";

  function _setSession(token, user) {
    try {
      sessionStorage.setItem(STORE_TOKEN, token);
      sessionStorage.setItem(STORE_USER, JSON.stringify(user || {}));
    } catch (e) {
      /* sessionStorage 不可用时静默降级（仅当前会话内存态） */
    }
  }
  function _clearSession() {
    try {
      sessionStorage.removeItem(STORE_TOKEN);
      sessionStorage.removeItem(STORE_USER);
    } catch (e) {
      /* noop */
    }
  }
  function _getUser() {
    try {
      const raw = sessionStorage.getItem(STORE_USER);
      return raw ? JSON.parse(raw) : null;
    } catch (e) {
      return null;
    }
  }

  /** 把登录用户写到右上用户卡（不写死，登录后覆盖默认占位）。 */
  function applyUser(user) {
    const card = document.getElementById("user-card");
    if (!card) return;
    const name = card.querySelector("b");
    const sub = card.querySelector("small");
    const avatar = card.querySelector(".avatar");
    const u = user || _getUser() || {};
    if (name) name.textContent = u.username || u.name || "用户";
    if (sub) {
      const roles = (u.roles || []).join(" · ") || (u.permissions ? "已登录" : "local");
      sub.textContent = roles;
    }
    if (avatar) avatar.textContent = (u.username || "U").slice(0, 1).toUpperCase();
  }

  /* ---------------- 登录页 UI ---------------- */
  function ensureMask() {
    let mask = document.getElementById("login-mask");
    if (mask) return mask;
    mask = document.createElement("div");
    mask.id = "login-mask";
    mask.setAttribute("data-testid", "login-mask");
    mask.setAttribute("role", "dialog");
    mask.setAttribute("aria-modal", "true");
    mask.innerHTML =
      '<div class="login-card">' +
      '<div class="login-brand"><span class="mark">J</span><div><b>鉴微 JianWei</b>' +
      "<small>AI 安全测试平台 · 统一控制台</small></div></div>" +
      '<form id="login-form" data-testid="login-form" autocomplete="off">' +
      '<label for="login-user">用户名</label>' +
      '<input id="login-user" data-testid="login-user" placeholder="admin" autocomplete="username" />' +
      '<label for="login-pass">密码</label>' +
      '<input id="login-pass" type="password" data-testid="login-pass" placeholder="••••••••" autocomplete="current-password" />' +
      '<button type="submit" id="login-submit" data-testid="login-submit" class="btn">登录</button>' +
      '<div id="login-error" data-testid="login-error" class="login-error" role="alert"></div>' +
      "</form>" +
      '<p class="login-hint">多用户模式：账号由部署时 JIANWEI_ADMIN_PASSWORD 设定。</p>' +
      "</div>";
    mask.style.cssText =
      "position:fixed;inset:0;z-index:1000;display:flex;align-items:center;justify-content:center;" +
      "background:rgba(15,23,42,.55);backdrop-filter:blur(2px)";
    document.body.appendChild(mask);

    const card = mask.querySelector(".login-card");
    card.style.cssText =
      "width:340px;max-width:92vw;background:#fff;border:1px solid #e5e7eb;border-radius:14px;padding:24px 22px;" +
      "box-shadow:0 12px 40px rgba(15,23,42,.18);font-family:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;color:#0f172a";
    const brand = mask.querySelector(".login-brand");
    brand.style.cssText = "display:flex;align-items:center;gap:10px;margin-bottom:18px";
    const mark = mask.querySelector(".mark");
    mark.style.cssText =
      "width:34px;height:34px;border-radius:9px;background:#2563eb;color:#fff;display:flex;align-items:center;" +
      "justify-content:center;font-weight:700;font-size:18px";
    mask.querySelector(".login-brand b").style.fontSize = "15px";
    mask.querySelector(".login-brand small").style.cssText = "display:block;color:#64748b;font-size:11px";
    const form = mask.querySelector("#login-form");
    form.style.cssText = "display:flex;flex-direction:column;gap:8px";
    form.querySelectorAll("label").forEach((l) => {
      l.style.cssText = "font-size:12px;color:#475569;margin-top:6px";
    });
    form.querySelectorAll("input").forEach((i) => {
      i.style.cssText =
        "padding:9px 11px;border:1px solid #cbd5e1;border-radius:8px;font-size:14px;outline:none";
      i.addEventListener("focus", () => (i.style.borderColor = "#2563eb"));
      i.addEventListener("blur", () => (i.style.borderColor = "#cbd5e1"));
    });
    const btn = mask.querySelector("#login-submit");
    btn.style.cssText =
      "margin-top:14px;padding:10px;border:none;border-radius:8px;background:#2563eb;color:#fff;font-size:14px;" +
      "font-weight:600;cursor:pointer";
    btn.addEventListener("mouseenter", () => (btn.style.background = "#1d4ed8"));
    btn.addEventListener("mouseleave", () => (btn.style.background = "#2563eb"));
    mask.querySelector(".login-hint").style.cssText = "margin:12px 0 0;font-size:11px;color:#94a3b8;text-align:center";
    const err = mask.querySelector("#login-error");
    err.style.cssText = "margin-top:8px;font-size:12px;color:#dc2626;min-height:16px";

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const username = mask.querySelector("#login-user").value.trim();
      const password = mask.querySelector("#login-pass").value;
      err.textContent = "";
      btn.disabled = true;
      btn.textContent = "登录中…";
      try {
        const data = await JW.login(username, password);
        hideLogin();
        applyUser(data.user);
        // 刷新当前视图，使其带 token 重新拉取数据
        window.dispatchEvent(new HashChangeEvent("hashchange"));
      } catch (ex) {
        err.textContent = ex && ex.message ? ex.message : "登录失败";
      } finally {
        btn.disabled = false;
        btn.textContent = "登录";
      }
    });
    return mask;
  }

  // 注意：遮罩创建时写了内联 `display:flex`，其优先级高于 `[hidden]{display:none}`，
  // 因此仅设 `hidden` 属性**关不掉**遮罩。必须同时显式改内联 display。
  function showLogin() {
    const mask = ensureMask();
    mask.hidden = false;
    mask.style.display = "flex";
    const u = mask.querySelector("#login-user");
    if (u) u.focus();
  }
  function hideLogin() {
    const mask = document.getElementById("login-mask");
    if (mask) {
      mask.hidden = true;
      mask.style.display = "none";
    }
  }

  /* ---------------- 对外 API ---------------- */
  /** 登录：调后端，存会话，返回 {token, user}。 */
  JW.login = async function (username, password) {
    const data = await JW.api.postJSON("/api/auth/login", { username, password });
    _setSession(data.token, data.user);
    return data;
  };

  /** 401 钩子：被 api.js 调用。 */
  JW.onUnauthorized = function () {
    _clearSession();
    showLogin();
  };

  /** 退出登录：清会话并弹回登录页。 */
  JW.logout = function () {
    // 尝试通知后端吊销（失败不影响前端清除）
    try {
      const t = sessionStorage.getItem(STORE_TOKEN);
      if (t) fetch("/api/auth/logout", { method: "POST", headers: { Authorization: "Bearer " + t } });
    } catch (e) {
      /* noop */
    }
    _clearSession();
    showLogin();
  };

  /* ---------------- 启动闸门 ---------------- */
  async function gate() {
    const token = (function () {
      try {
        return sessionStorage.getItem(STORE_TOKEN);
      } catch (e) {
        return null;
      }
    })();

    if (token) {
      try {
        const me = await JW.api.getJSON("/api/auth/me");
        applyUser(me);
        return; // 已登录，直接进入控制台
      } catch (e) {
        _clearSession(); // token 失效，落回登录流程
      }
    }

    // 无有效 token：依据平台配置决定是否弹登录页
    try {
      const info = await JW.api.getJSON("/api/platform/info");
      if (info && info.login_enabled) {
        showLogin();
        return;
      }
    } catch (e) {
      /* platform info 不可达：dev 模式通常也该可达；失败则不放闸门，避免误锁 */
    }
    // dev / 服务密钥模式：无需登录
  }

  // 脚本位于 body 末尾，DOM 已就绪，直接执行闸门
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", gate);
  } else {
    gate();
  }

  // 暴露给其它模块（如 app.js 用户卡）
  JW.applyUser = applyUser;
})(window.JW);

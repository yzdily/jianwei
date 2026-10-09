/* ============================================================
   鉴微控制台 · UI 工具层（DOM 助手 / Toast / 弹窗 / Markdown）
   ============================================================ */
window.JW = window.JW || {};

(function (JW) {
  "use strict";

  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

  /** HTML 转义：所有来自接口/用户的数据都必须经过它再进 innerHTML */
  function esc(v) {
    return String(v == null ? "" : v)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function sevBadge(sev) {
    const s = String(sev || "info").toLowerCase();
    return '<span class="sev ' + esc(s) + '">' + esc(s) + "</span>";
  }

  function kpi(label, value) {
    return '<div class="kpi"><b>' + esc(value) + "</b><span>" + esc(label) + "</span></div>";
  }

  function empty(text) {
    return '<div class="empty">' + esc(text) + "</div>";
  }

  /* ---------------- Toast ---------------- */
  function toast(msg, kind) {
    let box = $("#toasts");
    if (!box) {
      box = document.createElement("div");
      box.id = "toasts";
      box.className = "toasts";
      document.body.appendChild(box);
    }
    const t = document.createElement("div");
    t.className = "toast " + (kind || "");
    t.setAttribute("role", "status");
    t.textContent = msg;
    box.appendChild(t);
    // 4 秒后移除，避免长时间堆积遮挡内容
    setTimeout(() => t.remove(), 4000);
  }

  /* ---------------- 通用信息弹窗 ---------------- */
  function openModal(title, sub, bodyHtml) {
    $("#m-tt").textContent = title;
    $("#m-sub").textContent = sub || "";
    $("#m-body").innerHTML = bodyHtml || "";
    $("#m-mask").hidden = false;
    const close = $("#m-close");
    if (close) close.focus();
  }

  function closeModal() {
    const mask = $("#m-mask");
    if (mask) mask.hidden = true;
  }

  /* ---------------- 会话产物登记（下载记录只列真实产物，不造假数据） ------------- */
  const artifacts = [];

  /**
   * 登记一个可下载产物（报告 / SARIF / 扫描结果）。
   * @param {{name:string, kind:string, url:string, note?:string}} item
   */
  function addArtifact(item) {
    artifacts.unshift(Object.assign({ at: new Date().toLocaleTimeString() }, item));
    if (artifacts.length > 30) artifacts.pop();
  }

  function listArtifacts() {
    return artifacts.slice();
  }

  /** 行内语法：**粗体** 与 `代码`。入参必须已过 esc()，否则会引入 XSS */
  function _inline(escaped) {
    return escaped
      .replace(/\*\*(.+?)\*\*/g, "<b>$1</b>")
      .replace(/`([^`]+)`/g, "<code>$1</code>");
  }

  /* ---------------- 发现项表格（扫描/上传共用） ---------------- */
  /**
   * 渲染 findings 表格。字段兼容两套来源：
   * /api/scan/target → {name, severity, owasp, evidence}
   * /api/scan/skill/* → {name, severity, owasp, description, file_path, line}
   *
   * @param {Array<object>} findings 后端返回的发现项
   * @returns {string} 可直接塞进 innerHTML 的表格片段
   */
  function findingsTable(findings) {
    const list = Array.isArray(findings) ? findings : [];
    if (!list.length) return empty("未发现风险项。");
    let h =
      "<table><thead><tr><th>严重度</th><th>OWASP</th><th>名称</th><th>证据 / 描述</th><th>位置</th></tr></thead><tbody>";
    list.forEach((f) => {
      const ev = f.evidence || f.detail || f.description || "";
      const loc = f.file_path ? f.file_path + (f.line ? ":" + f.line : "") : "-";
      h +=
        "<tr><td>" +
        sevBadge(f.severity) +
        '</td><td class="mono">' +
        esc(f.owasp || "-") +
        "</td><td>" +
        esc(f.name || f.vuln_type || f.check_type || "") +
        '</td><td class="mono">' +
        esc(String(ev).slice(0, 200)) +
        "</td><td>" +
        esc(loc) +
        "</td></tr>";
    });
    return h + "</tbody></table>";
  }

  /* ---------------- 极简 Markdown → HTML ---------------- */
  function _flushCode(out, state) {
    if (state.inCode) {
      out.push('<pre class="md-src">' + esc(state.code.join("\n")) + "</pre>");
      state.inCode = false;
      state.code = [];
    }
  }

  function _renderTable(rows) {
    if (!rows.length) return "";
    const cells = (l) =>
      l.trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map((c) => c.trim());
    const isSep = (l) => cells(l).every((c) => /^:?-{2,}:?$/.test(c));
    const head = cells(rows[0]);
    const body = rows.slice(isSep(rows[1] || "") ? 2 : 1);
    let h = "<table><thead><tr>";
    head.forEach((c) => (h += "<th>" + esc(c) + "</th>"));
    h += "</tr></thead><tbody>";
    body.forEach((r) => {
      h += "<tr>";
      cells(r).forEach((c) => (h += "<td>" + esc(c) + "</td>"));
      h += "</tr>";
    });
    return h + "</tbody></table>";
  }

  /**
   * 把报告 markdown 渲染为 HTML（只支持报告实际用到的子集：
   * 标题 / 表格 / 列表 / 代码块 / 行内代码 / 加粗 / 段落），避免引入第三方依赖。
   */
  function mdToHtml(md) {
    const out = [];
    const state = { inCode: false, code: [], table: [] };
    const flushTable = () => {
      if (state.table.length) {
        out.push(_renderTable(state.table));
        state.table = [];
      }
    };

    String(md || "").split("\n").forEach((line) => {
      if (line.trim().startsWith("```")) {
        if (state.inCode) _flushCode(out, state);
        else {
          flushTable();
          state.inCode = true;
          state.code = [];
        }
        return;
      }
      if (state.inCode) {
        state.code.push(line);
        return;
      }
      if (/^\s*\|.*\|\s*$/.test(line)) {
        state.table.push(line);
        return;
      }
      flushTable();

      const h = /^(#{1,6})\s+(.*)$/.exec(line);
      if (h) {
        out.push("<h" + h[1].length + ">" + esc(h[2]) + "</h" + h[1].length + ">");
        return;
      }
      const li = /^\s*[-*]\s+(.*)$/.exec(line);
      if (li) {
        out.push("<li>" + _inline(esc(li[1])) + "</li>");
        return;
      }
      const ol = /^\s*\d+\.\s+(.*)$/.exec(line);
      if (ol) {
        out.push("<li>" + _inline(esc(ol[1])) + "</li>");
        return;
      }
      if (!line.trim()) {
        out.push("");
        return;
      }
      out.push("<p>" + _inline(esc(line)) + "</p>");
    });
    _flushCode(out, state);
    flushTable();
    return out.join("\n");
  }

  JW.ui = {
    $,
    $$,
    esc,
    sevBadge,
    kpi,
    empty,
    toast,
    openModal,
    closeModal,
    addArtifact,
    listArtifacts,
    findingsTable,
    mdToHtml,
  };
})(window.JW);

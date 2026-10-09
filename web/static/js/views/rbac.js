/* ============================================================
   VIEW 09 · 权限管理 —— 接 /api/rbac/*（子账号 / 用户组 / 角色）
   Demo 里这块只有界面；本视图接的是真实后端，增删都会落库（内存态）。
   ============================================================ */
window.JW = window.JW || {};
JW.viewList = JW.viewList || [];

(function (JW) {
  "use strict";
  const { $, $$, esc } = JW.ui;

  const TABS = [
    { id: "users", label: "子账号管理" },
    { id: "groups", label: "用户组管理" },
    { id: "roles", label: "角色管理" },
  ];

  let state = { tab: "users", data: null };

  function badgeList(ids, catalog) {
    if (!ids || !ids.length) return '<span class="tag">未分配</span>';
    return ids
      .map((id) => {
        const label = catalog && catalog[id] ? catalog[id] : id;
        return '<span class="tag">' + esc(label) + "</span>";
      })
      .join(" ");
  }

  function markup() {
    return (
      '<div class="v-tt"><span class="no">09</span><h2>权限管理</h2></div>' +
      '<p class="sub">子账号 / 用户组 / 角色的真实增删（<code>/api/rbac</code>）。权限目录是白名单，' +
      "后端会拒绝未知权限 id；被引用的组或角色会被拒删，避免权限静默失效。</p>" +
      '<div class="panel">' +
      '<div class="btn-row" role="tablist" style="margin-bottom:16px">' +
      TABS.map(
        (t) =>
          '<button class="btn ghost sm" role="tab" data-tab="' + t.id + '" data-testid="rbac-tab-' + t.id + '" ' +
          'aria-selected="' + (t.id === state.tab) + '">' + t.label + "</button>"
      ).join("") +
      '<button class="btn ghost sm" id="rbac-reload" data-testid="rbac-reload" style="margin-left:auto">刷新</button>' +
      "</div>" +
      '<div id="rbac-body" data-testid="rbac-body"></div>' +
      "</div>" +
      '<div class="panel" data-testid="rbac-perms"><div class="panel-tt"><h3>权限目录</h3>' +
      '<span class="tag" id="rbac-perm-count"></span></div>' +
      '<div class="tbl-wrap" id="rbac-perm-table"></div></div>'
    );
  }

  function tabButtons() {
    $$("[data-tab]").forEach((b) =>
      b.setAttribute("aria-selected", String(b.dataset.tab === state.tab))
    );
  }

  /* ---------------- 三个 Tab 的渲染 ---------------- */
  function renderUsers(d) {
    const roleName = Object.fromEntries(d.roles.map((r) => [r.id, r.name]));
    const groupName = Object.fromEntries(d.groups.map((g) => [g.id, g.name]));
    let h =
      '<div class="row"><div class="col"><label for="rbac-user-name">显示名</label>' +
      '<input id="rbac-user-name" data-testid="rbac-user-name" placeholder="张工" /></div>' +
      '<div class="col"><label for="rbac-user-email">邮箱</label>' +
      '<input id="rbac-user-email" placeholder="zhang@corp.local" /></div>' +
      '<div class="col fixed" style="width:140px;align-self:flex-end">' +
      '<button class="btn" id="rbac-add-user" data-testid="rbac-add-user">新建子账号</button></div></div>' +
      '<div class="tbl-wrap"><table><thead><tr><th>显示名</th><th>邮箱</th><th>用户组</th><th>角色</th><th></th></tr></thead><tbody>';
    d.users.forEach((u) => {
      h +=
        "<tr><td>" + esc(u.name) + '</td><td class="mono">' + esc(u.email || "-") + "</td><td>" +
        badgeList(u.groups, groupName) + "</td><td>" + badgeList(u.roles, roleName) +
        '</td><td><button class="btn danger sm" data-del-user="' + esc(u.id) + '">删除</button></td></tr>';
    });
    return h + "</tbody></table></div>";
  }

  function renderGroups(d) {
    const roleName = Object.fromEntries(d.roles.map((r) => [r.id, r.name]));
    let h =
      '<div class="row"><div class="col"><label for="rbac-group-name">组名</label>' +
      '<input id="rbac-group-name" data-testid="rbac-group-name" placeholder="红队组" /></div>' +
      '<div class="col" style="flex:2"><label for="rbac-group-desc">用途说明</label>' +
      '<input id="rbac-group-desc" placeholder="双轴扫描 · 报告处置" /></div>' +
      '<div class="col fixed" style="width:140px;align-self:flex-end">' +
      '<button class="btn" id="rbac-add-group" data-testid="rbac-add-group">新建用户组</button></div></div>' +
      '<div class="tbl-wrap"><table><thead><tr><th>组名</th><th>说明</th><th>角色</th><th>负责人</th><th></th></tr></thead><tbody>';
    d.groups.forEach((g) => {
      h +=
        "<tr><td>" + esc(g.name) + "</td><td>" + esc(g.desc || "-") + "</td><td>" +
        badgeList(g.roles, roleName) + '</td><td class="mono">' + esc(g.owner || "-") +
        '</td><td><button class="btn danger sm" data-del-group="' + esc(g.id) + '">删除</button></td></tr>';
    });
    return h + "</tbody></table></div>";
  }

  function renderRoles(d) {
    const permName = Object.fromEntries(d.permissions.map((p) => [p.id, p.name]));
    let h =
      '<div class="row"><div class="col"><label for="rbac-role-name">角色名</label>' +
      '<input id="rbac-role-name" data-testid="rbac-role-name" placeholder="只读审计员" /></div>' +
      '<div class="col" style="flex:2"><label for="rbac-role-desc">职责说明</label>' +
      '<input id="rbac-role-desc" placeholder="只读审计 · 报告导出" /></div></div>' +
      '<div class="row"><div class="col"><label>权限（多选，逗号分隔 id）</label>' +
      '<input id="rbac-role-perms" data-testid="rbac-role-perms" placeholder="scan.read,report.read" />' +
      '<div class="hint">可用 id：' +
      d.permissions.map((p) => esc(p.id)).join(" · ") +
      "</div></div>" +
      '<div class="col fixed" style="width:140px;align-self:flex-end">' +
      '<button class="btn" id="rbac-add-role" data-testid="rbac-add-role">新建角色</button></div></div>' +
      '<div class="tbl-wrap"><table><thead><tr><th>角色</th><th>说明</th><th>权限</th><th></th></tr></thead><tbody>';
    d.roles.forEach((r) => {
      h +=
        "<tr><td>" + esc(r.name) + "</td><td>" + esc(r.desc || "-") + "</td><td>" +
        badgeList(r.permissions, permName) +
        '</td><td><button class="btn danger sm" data-del-role="' + esc(r.id) + '">删除</button></td></tr>';
    });
    return h + "</tbody></table></div>";
  }

  function renderPerms(d) {
    $("#rbac-perm-count").textContent = d.permissions.length + " 项";
    $("#rbac-perm-table").innerHTML =
      "<table><thead><tr><th>权限 id</th><th>名称</th><th>分组</th></tr></thead><tbody>" +
      d.permissions
        .map(
          (p) =>
            '<tr><td class="mono">' + esc(p.id) + "</td><td>" + esc(p.name) +
            "</td><td>" + esc(p.group) + "</td></tr>"
        )
        .join("") +
      "</tbody></table>";
  }

  function renderBody() {
    const d = state.data;
    if (!d) return;
    const fn = { users: renderUsers, groups: renderGroups, roles: renderRoles }[state.tab];
    $("#rbac-body").innerHTML = fn(d);
    bindTabActions();
  }

  /* ---------------- 交互 ---------------- */
  function bindTabActions() {
    const d = state.data;

    const onAdd = async (path, payload, okMsg) => {
      try {
        await JW.api.postJSON(path, payload);
        JW.ui.toast(okMsg, "ok");
        await load();
      } catch (e) {
        JW.ui.toast(e.message, "bad");
      }
    };

    if (state.tab === "users") {
      $("#rbac-add-user").addEventListener("click", () => {
        const name = $("#rbac-user-name").value.trim();
        if (!name) return JW.ui.toast("请填写显示名", "warn");
        return onAdd(
          "/api/rbac/users",
          { name, email: $("#rbac-user-email").value.trim(), groups: [], roles: [] },
          "子账号已创建"
        );
      });
    }
    if (state.tab === "groups") {
      $("#rbac-add-group").addEventListener("click", () => {
        const name = $("#rbac-group-name").value.trim();
        if (!name) return JW.ui.toast("请填写组名", "warn");
        return onAdd(
          "/api/rbac/groups",
          { name, desc: $("#rbac-group-desc").value.trim(), roles: [] },
          "用户组已创建"
        );
      });
    }
    if (state.tab === "roles") {
      $("#rbac-add-role").addEventListener("click", () => {
        const name = $("#rbac-role-name").value.trim();
        if (!name) return JW.ui.toast("请填写角色名", "warn");
        const permissions = $("#rbac-role-perms")
          .value.split(",")
          .map((s) => s.trim())
          .filter(Boolean);
        return onAdd(
          "/api/rbac/roles",
          { name, desc: $("#rbac-role-desc").value.trim(), permissions },
          "角色已创建"
        );
      });
    }

    // 删除：后端对「内置账号 / 被引用的组与角色」会返回 409，此处原样呈现原因
    $$("[data-del-user], [data-del-group], [data-del-role]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const id = btn.dataset.delUser || btn.dataset.delGroup || btn.dataset.delRole;
        const path = btn.dataset.delUser
          ? "/api/rbac/users/" + id
          : btn.dataset.delGroup
            ? "/api/rbac/groups/" + id
            : "/api/rbac/roles/" + id;
        try {
          await JW.api.delJSON(path);
          JW.ui.toast("已删除", "ok");
          await load();
        } catch (e) {
          JW.ui.toast("删除失败：" + e.message, "bad");
        }
      });
    });
    if (d === null) return;
  }

  async function load() {
    $("#rbac-body").innerHTML = JW.ui.empty("加载中…");
    try {
      state.data = await JW.api.getJSON("/api/rbac/overview");
      renderBody();
      renderPerms(state.data);
    } catch (e) {
      $("#rbac-body").innerHTML = JW.ui.empty("加载失败：" + e.message);
    }
  }

  function mount(root) {
    root.innerHTML = markup();
    $$("[data-tab]").forEach((b) =>
      b.addEventListener("click", () => {
        state.tab = b.dataset.tab;
        tabButtons();
        renderBody();
      })
    );
    $("#rbac-reload").addEventListener("click", load);
    load();
  }

  JW.viewList.push({
    id: "rbac",
    no: "09",
    name: "权限管理",
    desc: "账号 / 组 / 角色",
    mount,
    refresh: load,
  });
})(window.JW);

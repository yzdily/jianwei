/* ============================================================
   VIEW 02 · 上传 Skill —— 接 POST /api/scan/skill/upload（multipart）
   原来只在独立向导页（:8099）存在，2026-10-09 收敛并入统一控制台。
   ============================================================ */
window.JW = window.JW || {};
JW.viewList = JW.viewList || [];

(function (JW) {
  "use strict";
  const { $ } = JW.ui;

  function markup() {
    return (
      '<div class="v-tt"><span class="no">02</span><h2>上传 Skill</h2></div>' +
      '<p class="sub">技能供应链静态扫描：<b>绝不执行</b>被扫对象，扫完即焚。' +
      "单文件 ≤ 1 MiB，压缩包 ≤ 100 MiB。实际调用 <code>POST /api/scan/skill/upload</code>（受理返回 202）。</p>" +
      '<div class="panel">' +
      '<div class="row">' +
      '<div class="col" style="flex:3"><label>技能包</label>' +
      '<div class="drop" id="skill-drop" data-testid="skill-drop" role="button" tabindex="0">' +
      '拖拽 zip / SKILL.md 到此处，或 <b>点击选择文件</b>' +
      '<input type="file" id="skill-file" data-testid="skill-file" accept=".zip,.tar.gz,.tgz,.md,.yaml,.yml,.json,.txt" />' +
      "</div>" +
      '<div class="hint" id="skill-picked" data-testid="skill-picked">未选择文件</div></div>' +
      '<div class="col fixed" style="width:170px"><label for="skill-strategy">扫描策略</label>' +
      '<select id="skill-strategy" data-testid="skill-strategy">' +
      '<option value="standard" selected>standard</option>' +
      '<option value="redteam">redteam</option></select>' +
      '<div class="hint">redteam 会启用 LLM 辅助判定</div></div>' +
      "</div>" +
      '<div class="btn-row">' +
      '<button class="btn" id="skill-upload" data-testid="skill-upload">上传并扫描</button>' +
      '<span class="hint" id="skill-status" data-testid="skill-status" role="status"></span>' +
      "</div></div>" +
      '<div class="panel" id="skill-result" data-testid="skill-result" hidden>' +
      '<div class="panel-tt"><h3 id="skill-verdict"></h3><span class="tag" id="skill-id"></span></div>' +
      '<div class="kpis" id="skill-kpis" data-testid="skill-kpis"></div>' +
      '<div class="tbl-wrap" id="skill-table" data-testid="skill-table"></div>' +
      '<div class="btn-row" style="margin-top:16px">' +
      '<a class="btn ghost" id="skill-sarif" data-testid="skill-sarif" href="#" target="_blank" rel="noopener">下载 SARIF 2.1.0</a>' +
      '<button class="btn ghost sm" id="skill-report">生成 LLM Top 10 报告</button>' +
      "</div></div>"
    );
  }

  let picked = null;

  function pick(file) {
    picked = file || null;
    $("#skill-picked").textContent = picked
      ? picked.name + " · " + (picked.size / 1024).toFixed(1) + " KB"
      : "未选择文件";
  }

  async function upload() {
    const status = $("#skill-status");
    if (!picked) {
      status.textContent = "请先选择技能包。";
      return;
    }
    const btn = $("#skill-upload");
    btn.disabled = true;
    status.textContent = "扫描中…";

    const fd = new FormData();
    fd.append("file", picked, picked.name);
    fd.append("strategy", $("#skill-strategy").value);

    try {
      const meta = await JW.api.postForm("/api/scan/skill/upload", fd);
      const detail = await JW.api.getJSON("/api/scan/skill/" + encodeURIComponent(meta.scan_id));
      render(meta, detail);
      status.textContent = "完成。";
      JW.ui.toast(
        meta.safe_to_install ? "技能包通过检查" : "技能包被判定为高风险",
        meta.safe_to_install ? "ok" : "bad"
      );
    } catch (e) {
      status.textContent = "失败：" + e.message;
      JW.ui.toast("上传扫描失败：" + e.message, "bad");
    } finally {
      btn.disabled = false;
    }
  }

  function render(meta, detail) {
    const safe = meta.safe_to_install;
    $("#skill-result").hidden = false;
    $("#skill-verdict").innerHTML = safe
      ? '<span class="badge ok">可安装</span> 未发现阻断级风险'
      : '<span class="badge bad">禁止安装</span> 命中高危供应链风险';
    $("#skill-id").textContent = meta.scan_id;
    $("#skill-kpis").innerHTML = [
      JW.ui.kpi("风险分", meta.risk_score),
      JW.ui.kpi("整体等级", meta.severity || "-"),
      JW.ui.kpi("发现数", detail.finding_count != null ? detail.finding_count : (detail.findings || []).length),
      JW.ui.kpi("可安装", safe ? "是" : "否"),
    ].join("");
    $("#skill-table").innerHTML = JW.ui.findingsTable(detail.findings);

    const sarifUrl = "/api/scan/skill/" + meta.scan_id + "/sarif";
    $("#skill-sarif").href = sarifUrl;
    JW.ui.addArtifact({
      name: meta.scan_id + " · " + (picked ? picked.name : "skill"),
      kind: "sarif",
      url: sarifUrl,
      note: "SARIF · " + (detail.finding_count || 0) + " 项",
    });
    JW.lastSkill = detail;
  }

  async function makeReport() {
    const d = JW.lastSkill;
    if (!d || !d.findings) return;
    try {
      const r = await JW.api.postJSON("/api/ai-sec/report/from-findings", {
        target_url: "skill://" + d.scan_id,
        findings: d.findings.map((f) => ({
          owasp: f.owasp || "LLM",
          vuln_type: f.check_type || f.name || "skill_risk",
          severity: f.severity || "info",
          url: f.file_path || "",
          detail: f.description || f.name || "",
          evidence: (f.description || "").slice(0, 300),
        })),
      });
      JW.ui.addArtifact({
        name: r.scan_id + " · Skill 扫描报告",
        kind: "md",
        url: "/api/ai-sec/report/" + r.scan_id,
        note: "Markdown",
      });
      JW.ui.toast("报告已生成：" + r.scan_id, "ok");
    } catch (e) {
      JW.ui.toast("生成报告失败：" + e.message, "bad");
    }
  }

  function mount(root) {
    root.innerHTML = markup();
    const drop = $("#skill-drop");
    const input = $("#skill-file");

    drop.addEventListener("click", () => input.click());
    drop.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        input.click();
      }
    });
    input.addEventListener("change", () => pick(input.files[0]));
    ["dragenter", "dragover"].forEach((ev) =>
      drop.addEventListener(ev, (e) => {
        e.preventDefault();
        drop.classList.add("over");
      })
    );
    ["dragleave", "drop"].forEach((ev) =>
      drop.addEventListener(ev, (e) => {
        e.preventDefault();
        drop.classList.remove("over");
      })
    );
    drop.addEventListener("drop", (e) => {
      if (e.dataTransfer.files.length) pick(e.dataTransfer.files[0]);
    });

    $("#skill-upload").addEventListener("click", upload);
    $("#skill-report").addEventListener("click", makeReport);
  }

  JW.viewList.push({
    id: "skill",
    no: "02",
    name: "上传 Skill",
    desc: "供应链扫描",
    mount,
  });
})(window.JW);

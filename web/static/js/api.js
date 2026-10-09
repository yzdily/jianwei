/* ============================================================
   鉴微控制台 · API 客户端
   零依赖：fetch 封装 + SSE-over-fetch（POST 不能用 EventSource）
   ============================================================ */
window.JW = window.JW || {};

(function (JW) {
  "use strict";

  /** 从错误响应里抽出最有用的一句话（FastAPI detail 优先） */
  async function _fail(res) {
    let detail = res.statusText || "请求失败";
    try {
      const body = await res.json();
      if (body && body.detail) detail = body.detail;
      else if (body && body.error) detail = body.error;
    } catch (e) {
      /* 非 JSON 响应，保留 statusText */
    }
    return new Error(res.status + " · " + detail);
  }

  async function getJSON(path) {
    const res = await fetch(path, { headers: { Accept: "application/json" } });
    if (!res.ok) throw await _fail(res);
    return res.json();
  }

  async function postJSON(path, body) {
    const res = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(body || {}),
    });
    if (!res.ok) throw await _fail(res);
    return res.json();
  }

  /** multipart 上传：不要手写 Content-Type，交给浏览器带 boundary */
  async function postForm(path, formData) {
    const res = await fetch(path, { method: "POST", body: formData });
    if (!res.ok) throw await _fail(res);
    return res.json();
  }

  async function getText(path) {
    const res = await fetch(path);
    if (!res.ok) throw await _fail(res);
    return res.text();
  }

  /** DELETE：204 无响应体，不能无条件 res.json()（会抛解析错） */
  async function delJSON(path) {
    const res = await fetch(path, { method: "DELETE" });
    if (!res.ok) throw await _fail(res);
    return res.status === 204 ? null : res.json().catch(() => null);
  }

  /**
   * 读取 SSE 流（后端契约：`event: <phase>\ndata: <json>\n\n`）。
   * 用 fetch + ReadableStream 而非 EventSource——因为端点是 POST。
   *
   * @param {string} path 端点
   * @param {object} body JSON 请求体
   * @param {(evt:{event:string,data:object})=>void} onEvent 每条事件回调
   * @param {AbortSignal} [signal] 用于取消
   */
  async function sse(path, body, onEvent, signal) {
    const res = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "text/event-stream" },
      body: JSON.stringify(body || {}),
      signal,
    });
    if (!res.ok) throw await _fail(res);

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buf = "";

    // 逐块解析：SSE 以空行分隔事件，跨块的半截消息要留在缓冲区
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });

      const blocks = buf.split("\n\n");
      buf = blocks.pop() || "";
      for (const block of blocks) {
        if (!block.trim()) continue;
        let name = "message";
        const dataLines = [];
        for (const line of block.split("\n")) {
          if (line.startsWith("event:")) name = line.slice(6).trim();
          else if (line.startsWith("data:")) dataLines.push(line.slice(5).trim());
        }
        let data = {};
        try {
          data = dataLines.length ? JSON.parse(dataLines.join("\n")) : {};
        } catch (e) {
          data = { raw: dataLines.join("\n") };
        }
        onEvent({ event: name, data });
      }
    }
  }

  JW.api = { getJSON, postJSON, postForm, getText, delJSON, sse };
})(window.JW);

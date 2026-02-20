const $ = (id) => document.getElementById(id);

const chatEl = $("chat");
const receiptsEl = $("receipts");
const llmEl = $("llm");

function pill(el, text, cls) {
  el.textContent = text;
  el.classList.remove("ok","bad");
  if (cls) el.classList.add(cls);
}

function appendMsg(role, content, meta={}, cls="") {
  const div = document.createElement("div");
  div.className = `msg ${role} ${cls}`.trim();
  div.innerHTML = `
    <div>${escapeHtml(content)}</div>
    <div class="meta">
      <span>${escapeHtml(meta.receipt_id || "")}</span>
      <span>${escapeHtml(meta.ts || "")}</span>
    </div>
  `;
  chatEl.appendChild(div);
  chatEl.scrollTop = chatEl.scrollHeight;
}

function escapeHtml(s){
  return String(s ?? "")
    .replaceAll("&","&amp;")
    .replaceAll("<","&lt;")
    .replaceAll(">","&gt;");
}

async function api(path, opts={}) {
  const res = await fetch(path, opts);
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { ok:false, raw:text.slice(0,800) }; }
  return { res, data };
}

async function refreshHealth() {
  const { res, data } = await api("/health");
  const serverPill = $("pill-server");
  const llmPill = $("pill-llm");
  const policyPill = $("pill-policy");

  if (!res.ok || !data.ok) {
    pill(serverPill, "server: offline", "bad");
    pill(llmPill, "llm: ?", "");
    pill(policyPill, "policy: ?", "");
    return;
  }
  pill(serverPill, "server: online", "ok");
  pill(policyPill, `policy: ${data.policy_mode ?? "?"}`, data.policy_mode === "normal" ? "ok" : "bad");

  // If you have /api/llm/status, show it. If not, just show "ollama".
  try {
    const s = await api("/api/llm/status");
    if (s.res.ok) {
      pill(llmPill, `llm: ${s.data.model ?? "?"}`, "ok");
      llmEl.textContent = JSON.stringify(s.data, null, 2);
    } else {
      pill(llmPill, "llm: unknown", "");
      llmEl.textContent = JSON.stringify(s.data, null, 2);
    }
  } catch {
    pill(llmPill, "llm: unknown", "");
  }
}

async function tailReceipts() {
  const { res, data } = await api("/api/receipts/tail?limit=10");
  receiptsEl.textContent = res.ok ? JSON.stringify(data, null, 2) : JSON.stringify(data, null, 2);
}

async function sendChat() {
  const text = $("input").value.trim();
  if (!text) return;
  $("input").value = "";

  appendMsg("user", text);

  const { res, data } = await api("/api/ingest", {
    method: "POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({ text })
  });

  if (!res.ok || data.outcome !== "COMMIT" || data.verdict !== "PASS") {
    appendMsg("assistant", data.error || "Request failed", { receipt_id: data.receipt_id || "", ts: "" }, "fail");
    await tailReceipts();
    await refreshHealth();
    return;
  }

  // Pull assistant unit content from receipt if present
  const units = (data.data && data.data.units) || [];
  const a = units.find(u => (u.body && u.body.role === "assistant")) || null;
  const reply = a?.body?.content || "(no assistant content)";
  appendMsg("assistant", reply, { receipt_id: data.receipt_id || "", ts: String(data.ts || "") });

  await tailReceipts();
  await refreshHealth();
}

async function exportCapsule() {
  const { res, data } = await api("/api/capsule/export", {
    method: "POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({ agent_id: "agent-x", profile: { label: "ui-export" } })
  });
  if (!res.ok || !data.ok) {
    appendMsg("assistant", "Export failed: " + (data.error || "unknown"), {}, "fail");
  } else {
    appendMsg("assistant", `Exported capsule:\n${data.path}`, {}, "");
  }
}

async function refreshModels() {
  // simplest: ask ollama directly from browser is blocked by CORS sometimes.
  // Better: add backend endpoint /api/ollama/tags later.
  // For now: keep a small manual list, but still editable.
  const sel = $("model");
  sel.innerHTML = "";
  const defaults = [
    "dolphin-llama3:latest",
    "llama3.2:latest",
    "llama3.1:8b-instruct-q6_K"
  ];
  for (const m of defaults) {
    const opt = document.createElement("option");
    opt.value = m; opt.textContent = m;
    sel.appendChild(opt);
  }

  // preselect current
  try {
    const s = await api("/api/llm/status");
    if (s.res.ok && s.data.model) sel.value = s.data.model;
  } catch {}
}

async function applyModel() {
  const model = $("model").value;
  const { res, data } = await api("/api/llm/config", {
    method: "POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({ backend: "ollama", model, base_url: "http://127.0.0.1:11434" })
  });
  if (!res.ok || !data.ok) {
    appendMsg("assistant", "Set model failed: " + JSON.stringify(data), {}, "fail");
  } else {
    appendMsg("assistant", "Model set to: " + model);
    await refreshHealth();
  }
}

$("send").addEventListener("click", sendChat);
$("input").addEventListener("keydown", (e) => { if (e.key === "Enter") sendChat(); });
$("tail").addEventListener("click", tailReceipts);
$("export").addEventListener("click", exportCapsule);
$("docs").addEventListener("click", () => window.open("/docs", "_blank"));

$("refreshModels").addEventListener("click", refreshModels);
$("applyModel").addEventListener("click", applyModel);

(async function boot(){
  await refreshModels();
  await refreshHealth();
  await tailReceipts();
})();

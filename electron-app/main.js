const { app, BrowserWindow, Tray, Menu, nativeImage, dialog, shell } = require("electron");

let mainWindow = null;
let tray = null;

const SERVER_URL = process.env.CC_URL || "http://127.0.0.1:7078/ui/";

function trayIcon() {
  const dataUrl =
    "data:image/png;base64," +
    "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAQAAAC1+jfqAAAAKElEQVR4AWP4z8Dwn4GBgYGJgQH4////B8QGgQk0Gg0AAJp8Cqv8d0xGAAAAAElFTkSuQmCC";
  return nativeImage.createFromDataURL(dataUrl);
}

function showOrCreate() {
  if (!mainWindow) createWindow();
  else {
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.show();
    mainWindow.focus();
  }
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 900,
    height: 700,
    show: false,
    webPreferences: { nodeIntegration: false, contextIsolation: true }
  });

  mainWindow.loadURL(SERVER_URL);

  mainWindow.once("ready-to-show", () => mainWindow.show());

  mainWindow.webContents.on("did-fail-load", async (_e, code, desc) => {
    await dialog.showMessageBox({
      type: "error",
      title: "Compatible Companion",
      message: "Failed to load backend UI.",
      detail:
        `URL: ${SERVER_URL}\n\nError ${code}: ${desc}\n\n` +
        `Start backend:\ncd ~/compatible && python -m uvicorn cc.api:app --host 127.0.0.1 --port 7078 --reload`
    });
  });

  mainWindow.on("closed", () => (mainWindow = null));
}

const BACKEND_OFFLINE_MSG = `Could not reach backend at ${SERVER_URL}\n\nMake sure it is running:\ncd ~/compatible && python -m uvicorn cc.api:app --host 127.0.0.1 --port 7078 --reload`;

async function exportCapsuleFromTray() {
  const url = new URL("/api/capsule/export", SERVER_URL).toString();

  const payload = {
    agent_id: "agent-x",
    profile: { label: "tray-export" }
  };

  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    const text = await res.text();
    let data;
    try {
      data = JSON.parse(text);
    } catch {
      data = { ok: false, error: "non_json_response", raw: text.slice(0, 800) };
    }

    if (!res.ok || !data.ok) {
      await dialog.showMessageBox({
        type: "error",
        title: "Export Capsule Failed",
        message: "Backend returned an error.",
        detail: JSON.stringify(data, null, 2)
      });
      return;
    }

    const outPath = data.path || "";
    const capsuleId = data.capsule_id || "";
    const detail =
      `Saved:\n${outPath}\n\n` +
      `capsule_id: ${capsuleId}\n` +
      `signed: ${String(!!data.signed)}\n` +
      `units: ${String(data.units ?? "n/a")}`;

    const result = await dialog.showMessageBox({
      type: "info",
      title: "Capsule Exported",
      message: "Export completed.",
      detail,
      buttons: ["OK", "Open Folder"],
      defaultId: 0
    });

    if (result.response === 1 && outPath) {
      shell.showItemInFolder(outPath);
    }
  } catch (err) {
    await dialog.showMessageBox({
      type: "error",
      title: "Export Capsule Failed",
      message: "Backend offline.",
      detail: BACKEND_OFFLINE_MSG + `\n\nError: ${err}`
    });
  }
}

// ---- helpers for LLM Status and Config ----

async function apiGet(path) {
  const url = new URL(path, SERVER_URL).toString();
  const res = await fetch(url);
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { ok: false, raw: text.slice(0, 800) }; }
  return { res, data };
}

async function apiPost(path, payload) {
  const url = new URL(path, SERVER_URL).toString();
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {})
  });
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { ok: false, raw: text.slice(0, 800) }; }
  return { res, data };
}

async function showLLMStatus() {
  try {
    const { res, data } = await apiGet("/api/llm/status");
    if (!res.ok) {
      await dialog.showMessageBox({
        type: "error",
        title: "LLM Status",
        message: "Backend returned an error.",
        detail: JSON.stringify(data, null, 2)
      });
      return;
    }

    const reach = await apiGet("/health");
    const detail =
      `backend: ${data.backend ?? "n/a"}\n` +
      `model: ${data.model ?? "n/a"}\n` +
      `base_url: ${data.base_url ?? "n/a"}\n\n` +
      `server_ok: ${String(!!reach.data?.ok)}\n` +
      `policy_mode: ${reach.data?.policy_mode ?? "n/a"}\n` +
      `state_hash: ${reach.data?.state_hash ?? "n/a"}`;

    await dialog.showMessageBox({
      type: "info",
      title: "LLM Status",
      message: "Current LLM configuration",
      detail
    });
  } catch (err) {
    await dialog.showMessageBox({
      type: "error",
      title: "LLM Status Failed",
      message: "Backend offline.",
      detail: BACKEND_OFFLINE_MSG + `\n\nError: ${err}`
    });
  }
}

async function setOllamaModel(modelTag) {
  const payload = {
    backend: "ollama",
    model: modelTag,
    base_url: "http://127.0.0.1:11434"
  };

  try {
    const { res, data } = await apiPost("/api/llm/config", payload);
    if (!res.ok || !data.ok) {
      await dialog.showMessageBox({
        type: "error",
        title: "Set Model Failed",
        message: "Backend returned an error.",
        detail: JSON.stringify(data, null, 2)
      });
      return;
    }

    await dialog.showMessageBox({
      type: "info",
      title: "Model Updated",
      message: "Active model has been updated.",
      detail: JSON.stringify(data.llm || data, null, 2)
    });
  } catch (err) {
    await dialog.showMessageBox({
      type: "error",
      title: "Set Model Failed",
      message: "Backend offline.",
      detail: BACKEND_OFFLINE_MSG + `\n\nError: ${err}`
    });
  }
}

// ---- createTray() ----

function createTray() {
  tray = new Tray(trayIcon());

  const menu = Menu.buildFromTemplate([
    { label: "Open Companion", click: () => showOrCreate() },

    { type: "separator" },

    { label: "LLM Status", click: () => showLLMStatus() },

    {
      label: "Set Ollama Model",
      submenu: [
        {
          label: "dolphin-llama3:latest",
          click: () => setOllamaModel("dolphin-llama3:latest")
        },
        {
          label: "llama3.2:latest",
          click: () => setOllamaModel("llama3.2:latest")
        },
        {
          label: "llama3.1:8b-instruct-q6_K",
          click: () => setOllamaModel("llama3.1:8b-instruct-q6_K")
        }
      ]
    },

    { type: "separator" },

    {
      label: "Export Capsule",
      click: () => exportCapsuleFromTray()
    },

    { label: "Reload UI", click: () => (mainWindow ? mainWindow.reload() : createWindow()) },
    { label: "Open /docs", click: () => shell.openExternal(new URL("/docs", SERVER_URL).toString()) },

    { type: "separator" },
    { label: "Quit", click: () => app.quit() }
  ]);

  tray.setToolTip("Compatible Companion");
  tray.setContextMenu(menu);
  tray.on("click", () => showOrCreate());
}

app.whenReady().then(() => {
  createWindow();
  createTray();
});

app.on("window-all-closed", () => { });

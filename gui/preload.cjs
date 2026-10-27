// What the window's page can reach: actions by name, the state, the log, and a few links.
const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("foxhole", {
  platform: process.platform,
  act: (name, ...args) => ipcRenderer.invoke("act", name, ...args),
  open: (which) => ipcRenderer.invoke("open", which),
  onState: (cb) => ipcRenderer.on("state", (_e, state) => cb(state)),
  onLog: (cb) => ipcRenderer.on("log", (_e, lines) => cb(lines)),
});

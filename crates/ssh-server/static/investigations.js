"use strict";
(() => {
  const root = document.querySelector(".content[data-operator]");
  const form = document.getElementById("export-evidence");
  const status = document.getElementById("export-status");
  const download = document.getElementById("export-download");
  if (!root || !form || !status || !download) return;
  const target = location.hash && document.getElementById(location.hash.slice(1));
  if (target && target.tagName === "DETAILS") target.open = true;
  let prepared = null, expiry = null, version = 0;
  const clear = message => {
    if (prepared) URL.revokeObjectURL(prepared);
    if (expiry) clearTimeout(expiry);
    prepared = null; expiry = null; download.hidden = true;
    if (message) status.textContent = message;
  };
  form.addEventListener("change", () => { version += 1; clear("Selection changed. Prepare the evidence again."); });
  document.addEventListener("activity-updated", () => {
    const results = document.getElementById("activity-results");
    if (!results) return;
    if (results.dataset.investigation) {
      for (const link of document.querySelectorAll("[data-investigation-link]")) link.href = results.dataset.investigation;
      for (const input of document.querySelectorAll('input[name="investigation"]')) input.value = results.dataset.investigation;
    }
    if (results.dataset.pageIds !== undefined) form.elements.page_ids.value = results.dataset.pageIds;
    version += 1; clear("The observation changed. Prepare evidence from the displayed view.");
  });
  addEventListener("pagehide", () => clear());
  form.addEventListener("submit", async event => {
    event.preventDefault();
    clear();
    const candidate = version;
    const button = form.querySelector('button[type="submit"]');
    button.disabled = true; status.textContent = "Preparing evidence…";
    try {
      const url = new URL(form.action, location.href);
      url.search = new URLSearchParams(new FormData(form)).toString();
      const response = await fetch(url, { credentials: "same-origin", cache: "no-store", redirect: "error" });
      if (!response.ok) {
        status.textContent = response.status === 413 ? "Limit reached. Narrow the range or exclude output previews." : "Preparation failed. Check source availability and sign-in, narrow the range, or retry.";
        return;
      }
      const outcome = response.headers.get("x-export-status");
      if (!["ready", "incomplete", "limit_reached"].includes(outcome)) throw new Error("Unexpected export response");
      const blob = await response.blob();
      if (candidate !== version) { status.textContent = "The view changed during preparation. Prepare again."; return; }
      const disposition = response.headers.get("content-disposition") || "";
      const filename = disposition.match(/filename="([a-zA-Z0-9._-]+)"/);
      prepared = URL.createObjectURL(blob); download.href = prepared;
      download.download = filename ? filename[1] : "activity-evidence.json";
      download.hidden = false;
      const count = response.headers.get("x-export-operations") || "0";
      const label = outcome === "ready" ? "Ready" : outcome === "incomplete" ? "Ready — incomplete evidence" : "Limit reached — bounded evidence prepared";
      status.textContent = `${label} · ${count} operations. The manifest describes coverage and limits.`;
      expiry = setTimeout(() => clear("Prepared download expired in this page. Prepare it again."), 300000);
    } catch {
      status.textContent = "Preparation unavailable. The download was not prepared; retry after checking source availability and sign-in.";
    } finally { button.disabled = false; }
  });

  const definitionForm = document.getElementById("view-definition");
  const viewStatus = document.getElementById("view-status");
  const remembered = document.getElementById("remembered-views");
  const save = document.getElementById("save-view");
  const reset = document.getElementById("reset-views");
  const remember = document.getElementById("remember-view");
  const name = document.getElementById("view-name");
  const imported = document.getElementById("import-view");
  if (!definitionForm || !viewStatus || !remembered || !save || !reset || !remember || !name || !imported) return;
  const keys = new Set(["session", "host", "principal", "q", "source", "before", "start", "end", "window", "kind", "view", "selected", "role", "request", "agreement", "run", "approval", "assessment", "time_basis", "service_start", "service_end", "instance"]);
  const valid = value => value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).every(key => ["version", "mode", "filters"].includes(key)) && value.version === 1 && ["recurring", "fixed"].includes(value.mode) && value.filters && typeof value.filters === "object" && !Array.isArray(value.filters) && Object.keys(value.filters).length <= keys.size && Object.entries(value.filters).every(([key, value]) => keys.has(key) && typeof value === "string" && value.length <= 512);
  const viewUrl = definition => {
    const url = new URL("/dashboard/activity", location.href);
    for (const [key, value] of Object.entries(definition.filters)) url.searchParams.set(key, value);
    return url;
  };
  const storageKey = "mcp-ssh-rs:views:" + root.dataset.operator;
  const read = () => {
    const value = JSON.parse(localStorage.getItem(storageKey) || "[]");
    if (!Array.isArray(value) || value.length > 20 || value.some(row => !row || typeof row.name !== "string" || row.name.length > 80 || !valid(row.definition))) throw new Error("Unsupported saved views");
    return value;
  };
  const render = () => {
    remembered.replaceChildren();
    for (const row of read()) {
      const item = document.createElement("li");
      const link = document.createElement("a"); link.textContent = row.name; link.href = viewUrl(row.definition);
      item.append(link); remembered.append(item);
    }
  };
  save.hidden = false; reset.hidden = false; save.disabled = true;
  remember.addEventListener("change", () => { save.disabled = !remember.checked; });
  try { render(); } catch { viewStatus.textContent = "Remembered views are unavailable in this browser. View definition files remain usable."; }
  reset.addEventListener("click", () => {
    try { localStorage.removeItem(storageKey); remembered.replaceChildren(); viewStatus.textContent = "Remembered filters for this operator were cleared."; }
    catch { viewStatus.textContent = "Remembered filters could not be cleared in this browser."; }
  });
  save.addEventListener("click", async () => {
    if (!remember.checked || !name.value.trim()) { viewStatus.textContent = "Enter a view name and choose device storage, or export a view definition file."; return; }
    try {
      const url = new URL(definitionForm.action, location.href); url.search = new URLSearchParams(new FormData(definitionForm)).toString();
      const response = await fetch(url, { credentials: "same-origin", cache: "no-store", redirect: "error" });
      if (!response.ok) throw new Error("View validation failed");
      const definition = await response.json(); if (!valid(definition)) throw new Error("Unsupported view definition");
      const rows = read().filter(row => row.name !== name.value.trim());
      if (rows.length >= 20) { viewStatus.textContent = "The device view limit is reached. Reset remembered views or export a definition file."; return; }
      rows.push({ name: name.value.trim(), definition }); localStorage.setItem(storageKey, JSON.stringify(rows)); render();
      viewStatus.textContent = "Filters remembered on this device for the signed-in operator. Results were not copied.";
    } catch { viewStatus.textContent = "The view could not be validated or remembered. Try exporting its definition instead."; }
  });
  imported.addEventListener("change", async () => {
    const file = imported.files[0]; if (!file) return;
    if (file.size > 16384) { viewStatus.textContent = "The definition exceeds the 16 KiB import limit."; return; }
    try {
      const value = JSON.parse(await file.text()); if (!valid(value)) throw new Error("Unsupported definition");
      location.assign(viewUrl(value));
    } catch { viewStatus.textContent = "The view definition is invalid or unsupported. No navigation or operation was performed."; }
  });
})();

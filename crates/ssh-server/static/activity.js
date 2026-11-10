"use strict";
(() => {
  const formatTimes = (root = document) => {
    for (const node of root.querySelectorAll("[data-epoch]")) {
      const seconds = Number(node.dataset.epoch);
      if (Number.isSafeInteger(seconds) && seconds >= 0 && seconds <= 4294967295) {
        const iso = new Date(seconds * 1000).toISOString();
        node.dateTime = iso;
        node.textContent = iso.replace("T", " ").replace(".000Z", " UTC");
      }
    }
  };
  formatTimes();
  const results = document.getElementById("activity-results");
  const freshness = document.getElementById("freshness");
  const pause = document.getElementById("pause-updates");
  const apply = document.getElementById("apply-updates");
  if (!results || !freshness || !pause || !apply) return;
  const target = location.hash && document.getElementById(location.hash.slice(1));
  if (target && target.tagName === "DETAILS") { target.open = true; target.scrollIntoView(); }
  const outcome = document.getElementById("decision-outcome");
  if (outcome) outcome.focus();
  let paused = false, pending = null, activeRequest = null;
  const context = document.getElementById("session-context");
  const regions = [results, context].filter(Boolean);
  const fingerprint = nodes => nodes.map(node => node.textContent + "|" + Array.from(node.querySelectorAll("[data-operation]")).map(row => row.dataset.operation).join("|")).join("|");
  const install = next => {
    const outcomeFocused = document.activeElement?.id === "decision-outcome";
    regions.forEach((region, index) => {
      const expanded = new Map(Array.from(region.querySelectorAll("details[id]")).map(row => [row.id, row.open]));
      const durations = new Map(Array.from(region.querySelectorAll("form.actions")).map(form => [form.getAttribute("action"), form.querySelector('select[name="duration"]')?.value]));
      region.replaceChildren(...Array.from(next[index].childNodes).map(node => document.importNode(node, true)));
      for (const row of region.querySelectorAll("details[id]")) if (expanded.has(row.id)) row.open = expanded.get(row.id);
      for (const form of region.querySelectorAll("form.actions")) {
        const select = form.querySelector('select[name="duration"]');
        const value = durations.get(form.getAttribute("action"));
        if (select && value !== undefined && Array.from(select.options).some(option => option.value === value)) select.value = value;
      }
      if (region.id === "activity-results") {
        if (next[index].dataset.investigation) region.dataset.investigation = next[index].dataset.investigation;
        if (next[index].dataset.pageIds !== undefined) region.dataset.pageIds = next[index].dataset.pageIds;
      }
    });
    if (outcomeFocused) document.getElementById("decision-outcome")?.focus({ preventScroll: true });
    pending = null;
    apply.hidden = true;
    freshness.textContent = "Updated just now";
    document.dispatchEvent(new CustomEvent("activity-updated"));
  };
  pause.hidden = false;
  pause.addEventListener("click", () => {
    paused = !paused;
    pause.textContent = paused ? "Resume updates" : "Pause updates";
    freshness.textContent = paused ? "Updates paused" : "Checking current activity…";
    if (paused) cancelRequest();
    else refresh();
  });
  apply.addEventListener("click", () => {
    if (pending) install(pending);
    pause.focus();
  });
  const cancelRequest = () => {
    const previous = activeRequest;
    activeRequest = null;
    previous?.abort();
  };
  const refresh = async () => {
    if (paused || activeRequest || document.hidden) return;
    const request = new AbortController();
    activeRequest = request;
    const deadline = setTimeout(() => request.abort(), 10000);
    try {
      const response = await fetch(location.href, { credentials: "same-origin", cache: "no-store", signal: request.signal });
      if (!response.ok || response.redirected) throw new Error("Activity unavailable");
      const page = new DOMParser().parseFromString(await response.text(), "text/html");
      if (activeRequest !== request || paused) return;
      formatTimes(page);
      const next = page.getElementById("activity-results");
      if (!next || next.dataset.source !== results.dataset.source) throw new Error("Activity unavailable");
      const nextRegions = regions.map(region => page.getElementById(region.id));
      if (nextRegions.some(region => !region)) throw new Error("Activity unavailable");
      const changed = fingerprint(nextRegions) !== fingerprint(regions);
      if (changed && regions.some(region =>
        region.contains(document.activeElement) && document.activeElement?.id !== "decision-outcome"
        || region.querySelector("details[open]:not(.review-request)"))) {
        pending = nextRegions;
        apply.hidden = false;
        freshness.textContent = "Activity updates available";
      } else if (changed) {
        install(nextRegions);
      } else {
        freshness.textContent = "Checked just now";
      }
      const notice = page.getElementById("activity-notice");
      if (notice) document.getElementById("activity-notice").textContent = notice.textContent;
    } catch {
      if (activeRequest === request) freshness.textContent = "Updates unavailable · last observation remains visible";
    } finally {
      clearTimeout(deadline);
      if (activeRequest === request) activeRequest = null;
    }
  };
  setInterval(refresh, results.dataset.source === "history" ? 15000 : 5000);
  window.addEventListener("pagehide", cancelRequest);
  window.addEventListener("pageshow", event => { if (event.persisted) refresh(); });
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) cancelRequest();
    else refresh();
  });
})();

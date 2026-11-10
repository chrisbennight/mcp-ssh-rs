"use strict";
(() => {
  const results = document.getElementById("activity-results");
  const freshness = document.getElementById("freshness");
  const pause = document.getElementById("pause-updates");
  const apply = document.getElementById("apply-updates");
  if (!results || !freshness || !pause || !apply) return;
  let paused = false, pending = null, inFlight = false;
  const fingerprint = node => Array.from(node.querySelectorAll("[data-operation]"))
    .map(row => row.dataset.operation + ":" + row.textContent).join("|");
  const install = next => {
    const open = new Set(Array.from(results.querySelectorAll("details[open]")).map(row => row.id));
    results.replaceChildren(...Array.from(next.childNodes).map(node => document.importNode(node, true)));
    for (const row of results.querySelectorAll("details")) if (open.has(row.id)) row.open = true;
    pending = null;
    apply.hidden = true;
    freshness.textContent = "Updated just now";
  };
  pause.hidden = false;
  pause.addEventListener("click", () => {
    paused = !paused;
    pause.textContent = paused ? "Resume updates" : "Pause updates";
    freshness.textContent = paused ? "Updates paused" : "Checking current activity…";
  });
  apply.addEventListener("click", () => {
    if (pending) install(pending);
    pause.focus();
  });
  setInterval(async () => {
    if (paused || inFlight || document.hidden) return;
    inFlight = true;
    try {
      const response = await fetch(location.href, { credentials: "same-origin", cache: "no-store" });
      if (!response.ok || response.redirected) throw new Error("Activity unavailable");
      const page = new DOMParser().parseFromString(await response.text(), "text/html");
      const next = page.getElementById("activity-results");
      if (!next || next.dataset.source !== results.dataset.source) throw new Error("Activity unavailable");
      const changed = fingerprint(next) !== fingerprint(results);
      if (changed && (results.contains(document.activeElement) || results.querySelector("details[open]"))) {
        pending = next;
        apply.hidden = false;
        freshness.textContent = "Activity updates available";
      } else if (changed) {
        install(next);
      } else {
        freshness.textContent = "Checked just now";
      }
      const notice = page.getElementById("activity-notice");
      if (notice) document.getElementById("activity-notice").textContent = notice.textContent;
    } catch {
      freshness.textContent = "Updates unavailable · last observation remains visible";
    } finally {
      inFlight = false;
    }
  }, results.dataset.source === "history" ? 15000 : 5000);
})();

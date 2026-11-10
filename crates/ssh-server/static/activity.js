"use strict";
(() => {
  const results = document.getElementById("activity-results");
  const freshness = document.getElementById("freshness");
  const pause = document.getElementById("pause-updates");
  const apply = document.getElementById("apply-updates");
  if (!results || !freshness || !pause || !apply) return;
  const target = location.hash && document.getElementById(location.hash.slice(1));
  if (target && target.tagName === "DETAILS") { target.open = true; target.scrollIntoView(); }
  const outcome = document.getElementById("decision-outcome");
  if (outcome) outcome.focus();
  let paused = false, pending = null, inFlight = false;
  const context = document.getElementById("session-context");
  const regions = [results, context].filter(Boolean);
  const fingerprint = nodes => nodes.map(node => node.textContent + "|" + Array.from(node.querySelectorAll("[data-operation]")).map(row => row.dataset.operation).join("|")).join("|");
  const install = next => {
    regions.forEach((region, index) => {
      const open = new Set(Array.from(region.querySelectorAll("details[open][id]")).map(row => row.id));
      region.replaceChildren(...Array.from(next[index].childNodes).map(node => document.importNode(node, true)));
      for (const row of region.querySelectorAll("details[id]")) if (open.has(row.id)) row.open = true;
    });
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
      const nextRegions = regions.map(region => page.getElementById(region.id));
      if (nextRegions.some(region => !region)) throw new Error("Activity unavailable");
      const changed = fingerprint(nextRegions) !== fingerprint(regions);
      if (changed && regions.some(region => region.contains(document.activeElement) || region.querySelector("details[open]"))) {
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
      freshness.textContent = "Updates unavailable · last observation remains visible";
    } finally {
      inFlight = false;
    }
  }, results.dataset.source === "history" ? 15000 : 5000);
})();

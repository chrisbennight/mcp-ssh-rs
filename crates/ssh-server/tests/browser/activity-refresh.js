"use strict";
(async () => {
  const assert = (condition, message) => { if (!condition) throw new Error(message); };
  const request = id => `<details class="review-request" id="${id}" data-operation="${id}" open><summary>${id}</summary><form class="actions" action="/dashboard/approvals/${id}"><button name="decision" value="approve">Approve once</button><button name="decision" value="approve-session">Approve session</button><select name="duration"><option value="session" selected>Session</option><option value="30">30 minutes</option></select></form></details>`;
  const outcome = '<section id="decision-outcome" role="status" tabindex="-1">Recorded decision <a href="/dashboard/approvals">Next request</a></section>';
  const page = contents => `<span id="freshness"></span><button id="pause-updates" hidden>Pause updates</button><button id="apply-updates" hidden>Apply updates</button><div id="activity-results" data-source="current">${contents}</div>`;
  const waitFor = async (condition, message) => {
    for (let attempt = 0; attempt < 50; attempt++) {
      if (condition()) return;
      await new Promise(resolve => setTimeout(resolve, 0));
    }
    throw new Error(message);
  };
  const create = async contents => {
    const frame = document.createElement("iframe");
    frame.title = "Disposable refresh test";
    const ready = new Promise(resolve => { frame.onload = resolve; });
    frame.src = "about:blank";
    document.body.append(frame);
    await ready;
    const win = frame.contentWindow, doc = win.document;
    doc.body.innerHTML = page(contents);
    const state = { win, doc, frame, html: page(contents), deadlines: new Map(), requests: [], hidden: false };
    state.respond = async () => new win.Response(state.html, { status: 200 });
    state.fetch = state.respond;
    win.fetch = (url, options) => { state.requests.push(options); return state.fetch(url, options); };
    win.setInterval = callback => { state.poll = callback; return 1; };
    let timer = 0;
    win.setTimeout = callback => { state.deadlines.set(++timer, callback); return timer; };
    win.clearTimeout = id => state.deadlines.delete(id);
    Object.defineProperty(doc, "hidden", { get: () => state.hidden });
    const script = doc.createElement("script");
    script.src = new URL("../../static/activity.js", location.href).href;
    await new Promise((resolve, reject) => {
      script.onload = resolve;
      script.onerror = () => reject(new Error("Production refresh script failed to load"));
      doc.head.append(script);
    });
    assert(typeof state.poll === "function", "Production polling did not initialize");
    return state;
  };
  const cases = [
    ["Confirmation focus does not hide the next request", outcome, async state => {
      assert(state.doc.activeElement.id === "decision-outcome", "Confirmation did not receive focus");
      state.html = page(outcome + request("next"));
      await state.poll();
      assert(state.doc.getElementById("next"), "Next request stayed hidden after approval");
      assert(state.doc.activeElement.id === "decision-outcome", "Confirmation focus was lost");
      assert(state.doc.getElementById("apply-updates").hidden, "An untouched queue required Apply");
    }],
    ["Expanded requests allow arrivals and preserve closed requests", request("first"), async state => {
      state.html = page(request("first") + request("second"));
      await state.poll();
      assert(state.doc.getElementById("second"), "A default-open request froze the queue");
      state.doc.getElementById("first").open = false;
      state.html = page(request("first") + request("second") + request("third"));
      await state.poll();
      assert(!state.doc.getElementById("first").open, "A collapsed request was reopened");
      assert(state.doc.getElementById("third"), "A later arrival was hidden");
    }],
    ["Duration stays with its request during automatic updates", request("first"), async state => {
      state.doc.querySelector("select").value = "30";
      state.html = page(request("first") + request("second"));
      await state.poll();
      assert(state.doc.getElementById("second"), "An unfocused duration stopped arrivals");
      assert(state.doc.querySelector("#first select").value === "30", "Chosen duration was reset");
      assert(state.doc.querySelector("#second select").value === "session", "Duration crossed into another request");
    }],
    ["Focused controls wait for Apply and keep their duration", request("first"), async state => {
      const select = state.doc.querySelector("select");
      select.value = "30";
      select.focus();
      state.html = page(request("first") + request("second"));
      await state.poll();
      assert(!state.doc.getElementById("second"), "An active control was replaced");
      assert(state.doc.activeElement === select, "Control focus was lost");
      assert(!state.doc.getElementById("apply-updates").hidden, "Pending changes were not offered");
      state.doc.getElementById("apply-updates").click();
      assert(state.doc.getElementById("second"), "Apply did not install arrivals");
      assert(state.doc.querySelector("#first select").value === "30", "Apply reset the chosen duration");
    }],
    ["Failed reads retain the observation and recover", request("first"), async state => {
      state.fetch = async () => new state.win.Response("unavailable", { status: 503 });
      await state.poll();
      assert(state.doc.getElementById("first"), "A failure erased the last observation");
      assert(state.doc.getElementById("freshness").textContent.includes("unavailable"), "Failure was silent");
      state.fetch = state.respond;
      state.html = page(request("recovered"));
      await state.poll();
      assert(state.doc.getElementById("recovered"), "Polling did not recover");
    }],
    ["A stalled read times out and permits a later refresh", request("first"), async state => {
      state.fetch = (_url, options) => new Promise((_resolve, reject) => {
        options.signal.addEventListener("abort", () => reject(new state.win.DOMException("Aborted", "AbortError")));
      });
      const stalled = state.poll();
      assert(state.deadlines.size === 1, "The request has no deadline");
      for (const expire of state.deadlines.values()) expire();
      await stalled;
      assert(state.doc.getElementById("freshness").textContent.includes("unavailable"), "Timeout was silent");
      state.fetch = state.respond;
      state.html = page(request("recovered"));
      await state.poll();
      assert(state.doc.getElementById("recovered"), "The timeout left polling stuck");
    }],
    ["Restoring a page ignores its abandoned response", request("first"), async state => {
      let release;
      state.fetch = () => new Promise(resolve => { release = resolve; });
      const abandoned = state.poll();
      state.win.dispatchEvent(new state.win.PageTransitionEvent("pagehide", { persisted: true }));
      assert(state.requests[0].signal.aborted, "Navigation left the request active");
      state.fetch = state.respond;
      state.html = page(request("restored"));
      state.win.dispatchEvent(new state.win.PageTransitionEvent("pageshow", { persisted: true }));
      await waitFor(() => state.doc.getElementById("restored"), "Returning to Review did not refresh");
      release(new state.win.Response(page(request("stale")), { status: 200 }));
      await abandoned;
      assert(state.doc.getElementById("restored"), "An old response replaced the restored queue");
    }],
    ["Returning to a visible tab refreshes immediately", request("first"), async state => {
      let release;
      state.fetch = () => new Promise(resolve => { release = resolve; });
      const abandoned = state.poll();
      state.hidden = true;
      state.doc.dispatchEvent(new state.win.Event("visibilitychange"));
      assert(state.requests[0].signal.aborted, "Hiding the tab left its read active");
      await state.poll();
      assert(state.requests.length === 1, "A hidden tab kept polling");
      state.fetch = state.respond;
      state.html = page(request("visible"));
      state.hidden = false;
      state.doc.dispatchEvent(new state.win.Event("visibilitychange"));
      await waitFor(() => state.doc.getElementById("visible"), "The visible tab waited for a reload");
      release(new state.win.Response(page(request("stale")), { status: 200 }));
      await abandoned;
      assert(state.doc.getElementById("visible"), "A hidden tab's response replaced its new observation");
    }],
    ["Pause abandons an active read and resume refreshes", request("first"), async state => {
      let release;
      state.fetch = () => new Promise(resolve => { release = resolve; });
      const abandoned = state.poll();
      state.doc.getElementById("pause-updates").click();
      release(new state.win.Response(page(request("paused-response")), { status: 200 }));
      await abandoned;
      assert(state.doc.getElementById("first"), "An in-flight read changed the paused view");
      assert(state.doc.getElementById("freshness").textContent === "Updates paused", "Pause feedback was overwritten");
      state.fetch = state.respond;
      state.html = page(request("resumed"));
      state.doc.getElementById("pause-updates").click();
      await waitFor(() => state.doc.getElementById("resumed"), "Resume did not refresh");
    }],
  ];
  const results = [];
  for (const [name, contents, run] of cases) {
    let state;
    try {
      state = await create(contents);
      await run(state);
      results.push({ name, passed: true });
    } catch (error) {
      results.push({ name, passed: false, error: error.message });
    } finally {
      state?.frame.remove();
    }
  }
  window.refreshTestResult = { status: "complete", passed: results.every(result => result.passed), results };
  document.getElementById("result").textContent = JSON.stringify(window.refreshTestResult, null, 2);
})();

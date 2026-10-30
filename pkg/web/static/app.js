(function () {
  "use strict";
  const page = document.body.dataset.page;
  const $ = (s) => document.querySelector(s);
  const token = localStorage.getItem("flowstallion-token") || "";
  const authOn = document.body.dataset.auth === "true";

  // Client-side role gates. The server renders role-specific controls
  // (trigger, cancel, approve/reject, YAML editor, Settings link) into the
  // HTML itself, so these flags only govern controls that JS generates
  // dynamically (dashboard trigger buttons, canary rollback, settings row
  // actions). Auth-off is admin-equivalent, matching the API's synthetic user.
  let role = authOn ? "" : "admin";
  function canOperate() { return role === "admin" || role === "operator"; }
  function canAdmin() { return role === "admin"; }

  function esc(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
  }
  function badge(status) {
    return '<span class="badge st-' + esc(status) + '">' + esc(status) + "</span>";
  }
  // Outcome colors: ok green; denied/invalid/conflict orange; not_found gray;
  // error red.
  function outcomeBadge(o) {
    let cls;
    if (o === "ok") cls = "oc-ok";
    else if (o === "not_found") cls = "oc-404";
    else if (o === "error") cls = "oc-500";
    else cls = "oc-4xx";
    return '<span class="badge ' + cls + '">' + esc(o) + "</span>";
  }
  function authHeaders() {
    return authOn && token ? { Authorization: "Bearer " + token } : {};
  }
  function goLogin() {
    localStorage.removeItem("flowstallion-token");
    location.href = "/login?next=" + encodeURIComponent(location.pathname);
  }
  // Page navigation carries the session token in the "flowstallion" query parameter
  // so the server can gate page renders (the token itself stays in
  // localStorage for the JSON API).
  function pagePath(p) {
    if (!authOn || !token || p.startsWith("/static") || p.startsWith("/login")) return p;
    return p + (p.includes("?") ? "&" : "?") + "flowstallion=" + encodeURIComponent(token);
  }
  async function getJSON(url) {
    const r = await fetch(url, { headers: authHeaders() });
    if (r.status === 401) { goLogin(); }
    if (!r.ok) {
      // Surface the API's error body (e.g. "ledger: line 3: ...") when present.
      let detail = "";
      try {
        const text = await r.text();
        if (text) {
          try { detail = JSON.parse(text).error || text; } catch (_) { detail = text; }
        }
      } catch (_) { /* body unreadable */ }
      throw new Error(url + " -> HTTP " + r.status + (detail ? ": " + detail : ""));
    }
    return r.json();
  }
  async function postJSON(url, body) {
    const r = await fetch(url, {
      method: "POST",
      headers: Object.assign({ "Content-Type": "application/json" }, authHeaders()),
      body: JSON.stringify(body || {}),
    });
    if (r.status === 401) { goLogin(); }
    let json = null;
    const text = await r.text();
    if (text) { try { json = JSON.parse(text); } catch (_) { /* ignore */ } }
    return { status: r.status, json };
  }
  async function delJSON(url) {
    const r = await fetch(url, { method: "DELETE", headers: authHeaders() });
    if (r.status === 401) { goLogin(); }
    let json = null;
    const text = await r.text();
    if (text) { try { json = JSON.parse(text); } catch (_) { /* ignore */ } }
    return { status: r.status, json };
  }
  function errMsg(res) {
    const j = res.json;
    if (!j) return "HTTP " + res.status;
    if (j.error) return j.error;
    if (j.problems && j.problems.length) return j.problems.join("; ");
    return "HTTP " + res.status;
  }
  function setMsg(sel, text, isErr) {
    const el = $(sel);
    if (!el) return;
    el.textContent = text;
    el.className = isErr ? "error" : "muted";
  }

  // --- time helpers ------------------------------------------------------
  function fmtRel(iso) {
    if (!iso) return "—";
    const t = Date.parse(iso);
    if (isNaN(t)) return String(iso);
    const s = Math.max(0, (Date.now() - t) / 1000);
    if (s < 60) return "just now";
    if (s < 3600) return Math.floor(s / 60) + "m ago";
    if (s < 86400) return Math.floor(s / 3600) + "h ago";
    if (s < 86400 * 30) return Math.floor(s / 86400) + "d ago";
    return new Date(t).toISOString().slice(0, 10);
  }
  function fmtDur(started, finished) {
    if (!started) return "—";
    const s0 = Date.parse(started);
    if (isNaN(s0)) return "—";
    const s1 = finished ? Date.parse(finished) : NaN;
    if (isNaN(s1)) return "running…";
    const secs = Math.max(0, Math.round((s1 - s0) / 1000));
    const h = Math.floor(secs / 3600), m = Math.floor((secs % 3600) / 60), s = secs % 60;
    if (h) return h + "h" + m + "m";
    if (m) return m + "m" + s + "s";
    return s + "s";
  }
  // last7Days: UTC day keys ("YYYY-MM-DD") of the 7 days ending today, oldest
  // first.
  function last7Days() {
    const now = new Date();
    const out = [];
    for (let i = 6; i >= 0; i--) {
      out.push(new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - i))
        .toISOString().slice(0, 10));
    }
    return out;
  }
  function fmtMoney(v) { return "$" + Number(v).toFixed(4); }

  function runTable(runs, nameOf) {
    if (!runs.length) return '<p class="muted">No runs yet.</p>';
    return "<table><thead><tr><th>ID</th><th>Pipeline</th><th>Status</th>" +
      "<th>Trigger</th><th>Ref</th><th>Started</th><th>Duration</th></tr></thead><tbody>" +
      runs.map((r) =>
        '<tr><td><a href="' + pagePath("/run/" + r.id) + '"> #' + r.id + "</a></td>" +
        '<td><a href="' + pagePath("/pipeline/" + encodeURIComponent(nameOf[r.pipeline_id] || "")) + '">' +
        esc(nameOf[r.pipeline_id] || ("#" + r.pipeline_id)) + "</a></td>" +
        "<td>" + badge(r.status) + "</td><td>" + esc(r.trigger) + "</td>" +
        "<td>" + esc(r.source_ref || "") + "</td>" +
        '<td title="' + esc(r.started_at || "") + '">' + esc(fmtRel(r.started_at)) + "</td>" +
        "<td>" + esc(fmtDur(r.started_at, r.finished_at)) + "</td></tr>"
      ).join("") + "</tbody></table>";
  }

  // --- home / dashboard ---------------------------------------------------
  async function home() {
    const pEl = $("#pipelines");
    const rEl = $("#runs");
    const chartEl = $("#chart-7d");
    // M1: cost 400 (e.g. a ledger half-line -> /api/cost 400) used to reject
    // the whole Promise.all, freezing #runs and #chart-7d on "Loading…".
    // Fetch the three regions independently and degrade each one on its own:
    // a cost failure only blanks the cost stat + notes the chart area; it
    // never blocks pipelines, runs, or the 7-day chart from rendering.
    const [pipesR, runsR, costR] = await Promise.allSettled([
      getJSON("/api/pipelines"),
      getJSON("/api/runs?limit=200"),
      getJSON("/api/cost"),
    ]);

    const reasonMsg = (r) => (r.reason && r.reason.message) || String(r.reason);
    const days = last7Days();
    const windowStart = Date.parse(days[0] + "T00:00:00Z");

    // --- stats strip: each cell degrades to a placeholder on missing data ---
    $("#stat-pipelines").textContent =
      pipesR.status === "fulfilled" ? String(pipesR.value.length) : "—";
    let recent = [];
    if (runsR.status === "fulfilled") {
      recent = runsR.value.filter((r) => {
        const t = Date.parse(r.started_at || r.created_at || "");
        return !isNaN(t) && t >= windowStart;
      });
    }
    const runsAll = runsR.status === "fulfilled" ? runsR.value : [];
    // /api/runs?limit=200 caps at 200: a full page means the 7-day counts
    // below are lower bounds — surface that instead of a silently truncated
    // number.
    const truncated = runsAll.length >= 200;
    const runsEl = $("#stat-runs");
    runsEl.textContent =
      runsR.status === "fulfilled"
        ? (truncated ? "200+" : String(recent.length))
        : "—";
    if (truncated) {
      runsEl.title = "API caps at the 200 most-recent runs; the 7-day count is a lower bound";
    }
    const ok = recent.filter((r) => r.status === "success").length;
    const bad = recent.filter((r) => r.status === "failed").length;
    const successEl = $("#stat-success");
    successEl.textContent =
      ok + bad > 0 ? Math.round((ok / (ok + bad)) * 100) + "%" : "—";
    if (truncated) {
      successEl.title = "Computed over the 200 most-recent runs only (API cap)";
    }
    if (costR.status === "fulfilled") {
      const tot = costR.value && costR.value.total;
      $("#stat-cost").textContent = tot && tot.records ? fmtMoney(tot.cost_usd) : "—";
    } else {
      // cost unavailable: placeholder value + full error on hover.
      $("#stat-cost").textContent = "cost: err";
      $("#stat-cost").title = "cost: " + reasonMsg(costR);
    }

    // --- 7-day run chart (runs region) + cost error note (chart area) ---
    let chartHTML;
    if (runsR.status !== "fulfilled") {
      chartHTML = '<p class="error">Failed to load runs: ' + esc(reasonMsg(runsR)) + "</p>";
    } else {
      const runs = runsR.value;
      const buckets = {};
      for (const d of days) buckets[d] = { success: 0, failed: 0, running: 0, other: 0 };
      for (const r of runs) {
        const ts = r.started_at || r.created_at || "";
        const k = ts.slice(0, 10);
        if (!buckets[k]) continue; // outside the 7-day window (or malformed ts)
        if (r.status === "success") buckets[k].success++;
        else if (r.status === "failed") buckets[k].failed++;
        else if (r.status === "running") buckets[k].running++;
        else buckets[k].other++;
      }
      // "insufficient sample": the fetch hit the 200-run cap and even the
      // oldest fetched run falls inside the window, so older runs may be
      // missing from the chart.
      let sampleNote = "";
      if (runs.length >= 200) {
        const oldest = Math.min.apply(null,
          runs.map((r) => Date.parse(r.started_at || r.created_at || "") || Infinity));
        if (oldest !== Infinity && oldest >= windowStart) {
          sampleNote = "insufficient sample: limited to the 200 most recent runs";
        }
      }
      chartHTML =
        PHChart.svgStacked(days, buckets) +
        PHChart.legend([
          { color: "#2da44e", label: "success" },
          { color: "#d73a49", label: "failed" },
          { color: "#388bfd", label: "running" },
          { color: "#8c959f", label: "other" },
        ]) +
        (sampleNote ? '<p class="muted">' + esc(sampleNote) + "</p>" : "");
    }
    // A cost failure is surfaced in the chart area as a note (never clobbers
    // the run chart above it).
    if (costR.status === "rejected") {
      chartHTML += '<p class="error">Cost unavailable: ' + esc(reasonMsg(costR)) + "</p>";
    }
    chartEl.innerHTML = chartHTML;

    // --- pipelines table (trigger button for operator+) ---
    if (pipesR.status !== "fulfilled") {
      pEl.innerHTML = '<p class="error">Failed to load pipelines: ' + esc(reasonMsg(pipesR)) + "</p>";
      return;
    }
    const pipes = pipesR.value;
    if (!pipes.length) {
      pEl.innerHTML = '<p class="muted">No pipelines yet. Create one with <code>flowstallion create flowstallion.yaml</code>.</p>';
    } else {
      pEl.innerHTML =
        "<table><thead><tr><th>Name</th><th>Updated</th>" +
        (canOperate() ? "<th></th>" : "") + "</tr></thead><tbody>" +
        pipes.map((p) =>
          '<tr><td><a href="' + pagePath("/pipeline/" + encodeURIComponent(p.name)) + '">' +
          esc(p.name) + "</a></td>" +
          '<td title="' + esc(p.updated_at || "") + '">' + esc(fmtRel(p.updated_at)) + "</td>" +
          (canOperate()
            ? '<td><button class="btn tsm" data-trigger-pipe="' + esc(p.name) + '">Trigger</button></td>'
            : "") +
          "</tr>"
        ).join("") + "</tbody></table>";
      pEl.querySelectorAll("[data-trigger-pipe]").forEach((b) => {
        b.addEventListener("click", async () => {
          b.disabled = true;
          const res = await postJSON(
            "/api/pipelines/" + encodeURIComponent(b.dataset.triggerPipe) + "/trigger",
            { trigger: "manual" }
          );
          if (res.status === 202 && res.json && res.json.run_id) {
            location.href = pagePath("/run/" + res.json.run_id);
          } else {
            b.disabled = false;
            b.textContent = "Trigger failed";
            window.alert("Trigger failed: " + errMsg(res));
          }
        });
      });
    }

    // --- recent runs table ---
    if (runsR.status === "fulfilled") {
      const runs = runsR.value;
      const nameOf = {};
      pipes.forEach((p) => { nameOf[p.id] = p.name; });
      rEl.innerHTML = runTable(runs.slice(0, 10), nameOf);
    } else {
      rEl.innerHTML = '<p class="error">Failed to load runs: ' + esc(reasonMsg(runsR)) + "</p>";
    }
  }

  // --- pipeline page --------------------------------------------------------
  const CANARY_TERMINAL = ["promoted", "rolled_back", "failed"];

  async function renderCanaries(name) {
    const el = $("#canaries");
    if (!el) return;
    let all;
    try {
      all = await getJSON("/api/canaries");
    } catch (e) {
      el.innerHTML = '<p class="error">Failed to load canaries: ' + esc(e.message) + "</p>";
      return;
    }
    const mine = (all || []).filter((c) => c.name === name);
    if (!mine.length) {
      el.innerHTML = '<p class="muted">No canary releases for this pipeline yet.</p>';
      return;
    }
    el.innerHTML =
      "<table><thead><tr><th>State</th><th>Canary image</th><th>Namespace</th>" +
      "<th>Started</th><th></th></tr></thead><tbody>" +
      mine.map((c) =>
        "<tr><td>" + badge(c.state) + "</td><td>" + esc(c.canary_image) + "</td>" +
        "<td>" + esc(c.namespace) + "</td>" +
        '<td title="' + esc(c.created_at || "") + '">' + esc(fmtRel(c.created_at)) + "</td>" +
        "<td>" + (canOperate() && !CANARY_TERMINAL.includes(c.state)
          ? '<button class="btn danger tsm" data-rollback-canary="' + c.id + '">Rollback</button>'
          : "") + "</td></tr>"
      ).join("") + "</tbody></table>";
    el.querySelectorAll("[data-rollback-canary]").forEach((b) => {
      b.addEventListener("click", async () => {
        const id = b.dataset.rollbackCanary;
        if (!confirm("Rollback canary #" + id + "? The stable image will be restored.")) return;
        b.disabled = true;
        const res = await postJSON("/api/canaries/" + id + "/rollback", {});
        if (res.status === 200) { location.reload(); }
        else {
          b.disabled = false;
          window.alert("Rollback failed: " + errMsg(res));
        }
      });
    });
  }

  async function pipelinePage() {
    const name = document.body.dataset.name;
    const rEl = $("#runs");
    try {
      const pipes = await getJSON("/api/pipelines");
      const me = pipes.find((p) => p.name === name);
      if (!me) { rEl.innerHTML = '<p class="error">Pipeline not found.</p>'; return; }
      const runs = await getJSON("/api/runs?pipeline_id=" + me.id + "&limit=50");
      rEl.innerHTML = runTable(runs, { [me.id]: me.name });

      // YAML: editable for admin, read-only for viewer/operator.
      const yamlBox = $("#yaml");
      const yamlView = $("#yaml-view");
      if (yamlBox) yamlBox.value = me.yaml || "";
      if (yamlView) yamlView.textContent = me.yaml || "(no YAML stored)";
      const saveBtn = $("#yaml-save");
      if (saveBtn) {
        saveBtn.addEventListener("click", async () => {
          const err = $("#yaml-error");
          saveBtn.disabled = true;
          err.textContent = "";
          const res = await postJSON("/api/pipelines", { name: name, yaml: yamlBox.value });
          if (res.status === 200 || res.status === 201) {
            location.reload();
          } else {
            saveBtn.disabled = false;
            if (err) err.textContent = errMsg(res);
            setMsg("#yaml-msg", "Save failed.");
          }
        });
      }

      const trig = $("#trigger");
      if (trig) {
        trig.addEventListener("click", async () => {
          trig.disabled = true;
          const res = await postJSON(
            "/api/pipelines/" + encodeURIComponent(name) + "/trigger",
            { trigger: "manual" }
          );
          if (res.status === 202 && res.json && res.json.run_id) {
            location.href = pagePath("/run/" + res.json.run_id);
          } else {
            trig.disabled = false;
            $("#trigger-msg").textContent = "Trigger failed: " + errMsg(res);
          }
        });
      }

      renderCanaries(name);
    } catch (e) {
      rEl.innerHTML = '<p class="error">Failed to load: ' + esc(e.message) + "</p>";
    }
  }

  // --- run page -------------------------------------------------------------
  const TERMINAL = ["success", "failed", "canceled", "rejected"];
  let logTimer = null;
  let statusTimer = null;
  let currentStep = null;
  let lastSeq = 0;

  function stopTimers() {
    if (logTimer) { clearInterval(logTimer); logTimer = null; }
    if (statusTimer) { clearInterval(statusTimer); statusTimer = null; }
  }

  function renderSteps(steps) {
    $("#steps").innerHTML =
      "<table><thead><tr><th>Step</th><th>Status</th><th>Image</th>" +
      "<th>Started</th><th>Finished</th></tr></thead><tbody>" +
      steps.map((s) =>
        '<tr class="step-row' + (s.step_id === currentStep ? " active" : "") +
        '" data-step="' + esc(s.step_id) + '"><td>' + esc(s.step_id) + "</td>" +
        "<td>" + badge(s.status) + "</td><td>" + esc(s.image) + "</td>" +
        '<td title="' + esc(s.started_at || "") + '">' + esc(fmtRel(s.started_at)) + "</td>" +
        '<td title="' + esc(s.finished_at || "") + '">' + esc(fmtRel(s.finished_at)) + "</td></tr>"
      ).join("") + "</tbody></table>";
    document.querySelectorAll(".step-row").forEach((tr) => {
      tr.addEventListener("click", () => selectStep(tr.dataset.step));
    });
  }

  async function loadRun() {
    const id = document.body.dataset.run;
    const data = await getJSON("/api/runs/" + id);
    const r = data.run;
    $("#run-info").innerHTML =
      "<p>Status: " + badge(r.status) +
      " &nbsp; Trigger: " + esc(r.trigger) +
      (r.source_ref ? " &middot; " + esc(r.source_ref) : "") +
      "<br>Started: " + esc(r.started_at || "&mdash;") +
      " &nbsp; Finished: " + esc(r.finished_at || "&mdash;") + "</p>";
    renderSteps(data.steps);
    renderAnalysis(data.analysis);
    renderPrReview(data.analyses);
    renderTestSelection(data.analyses);
    renderScans(data.scans);
    updateApproval(r.status);
    return data;
  }

  function verdictBadge(verdict) {
    const cls =
      verdict === "approve" ? "st-approve"
      : verdict === "request_changes" ? "st-request_changes"
      : "st-comment";
    return '<span class="badge ' + cls + '">' + esc(verdict) + "</span>";
  }

  function findAnalysis(analyses, kind) {
    if (!analyses) return null;
    for (const a of analyses) { if (a.kind === kind) return a; }
    return null;
  }

  function parseDetail(a) {
    if (!a || !a.detail) return null;
    try { return JSON.parse(a.detail); } catch (_) { return null; }
  }

  function renderPrReview(analyses) {
    const card = $("#pr-review-card");
    if (!card) return;
    const a = findAnalysis(analyses, "pr_review");
    if (!a) { card.hidden = true; return; }
    card.hidden = false;
    const el = $("#pr-review");
    const d = parseDetail(a);
    const verdict = (d && d.verdict) || "comment";
    const findings = (d && d.findings) || [];
    let html = "<p>" + verdictBadge(verdict) +
      (d && d.blocking ? " &nbsp; " + esc(String(d.blocking)) + " blocking finding(s)" : "") +
      "</p>";
    if (a.root_cause) html += "<p>" + esc(a.root_cause) + "</p>";
    if (d && d.summary) html += '<p class="muted">' + esc(d.summary) + "</p>";
    if (findings.length) {
      html +=
        "<table><thead><tr><th>Severity</th><th>Category</th>" +
        "<th>Location</th><th>Message</th></tr></thead><tbody>" +
        findings.map((f) =>
          "<tr><td>" + badge(f.severity || "info") + "</td>" +
          "<td>" + esc(f.category || "") + "</td><td>" +
          esc(f.path || "") + (f.line ? ":" + esc(f.line) : "") +
          "</td><td>" + esc(f.message || "") + "</td></tr>"
        ).join("") + "</tbody></table>";
    } else {
      html += '<p class="muted">No findings.</p>';
    }
    if (a.suggested_fix) {
      html += "<p>Suggested fix: " + esc(a.suggested_fix) + "</p>";
    }
    el.innerHTML = html;
  }

  function renderTestSelection(analyses) {
    const card = $("#test-selection-card");
    if (!card) return;
    const a = findAnalysis(analyses, "test_selection");
    if (!a) { card.hidden = true; return; }
    card.hidden = false;
    const el = $("#test-selection");
    const d = parseDetail(a) || {};
    const list = (items, empty) => items && items.length
      ? "<ul class=\"test-list\">" +
        items.map((t) => "<li><code>" + esc(t) + "</code></li>").join("") +
        "</ul>"
      : '<p class="muted">' + empty + "</p>";
    let html = "";
    if (a.root_cause) html += "<p>" + esc(a.root_cause) + "</p>";
    html +=
      "<div class=\"row\"><div><h3>Go tests</h3>" +
      list(d.go_tests, "No Go tests selected.") +
      "</div><div><h3>Python tests</h3>" +
      list(d.python_tests, "No Python tests selected.") +
      "</div></div>";
    const full = [];
    if (d.all_go) full.push("all Go tests");
    if (d.all_python) full.push("all Python tests");
    if (full.length) {
      html += '<p class="muted">Full suite will run: ' + esc(full.join(", ")) + "</p>";
    }
    const reasons = d.reasons || {};
    const reasonKeys = Object.keys(reasons);
    if (reasonKeys.length) {
      html +=
        "<details><summary>Reasons</summary><table><tbody>" +
        reasonKeys.map((k) =>
          "<tr><td><code>" + esc(k) + "</code></td>" +
          "<td>" + esc(reasons[k]) + "</td></tr>"
        ).join("") + "</tbody></table></details>";
    }
    el.innerHTML = html;
  }

  function renderScans(scans) {
    const el = $("#scans");
    if (!el) return;
    if (!scans || !scans.length) {
      el.innerHTML = '<p class="muted">No scans yet.</p>';
      return;
    }
    const rows = scans.map((s) => {
      const sev = s.severity
        ? Object.keys(s.severity).map((k) => k + ":" + s.severity[k]).join(" ")
        : "";
      let html =
        "<tr><td>" + esc(s.tool) + "</td><td>" + esc(s.target || "") + "</td>" +
        "<td>" + esc(s.mode) + "</td><td>" + s.exit_code + "</td>" +
        "<td>" + s.findings_count + "</td><td>" + esc(sev) + "</td>" +
        '<td title="' + esc(s.created_at || "") + '">' + esc(fmtRel(s.created_at)) + "</td></tr>";
      if (s.report_json) {
        html +=
          '<tr><td colspan="7"><details><summary>raw report' +
          (s.truncated ? " (truncated)" : "") +
          '</summary><pre class="logbox">' + esc(s.report_json) + "</pre></details></td></tr>";
      }
      return html;
    });
    el.innerHTML =
      "<table><thead><tr><th>Tool</th><th>Target</th><th>Mode</th>" +
      "<th>Exit</th><th>Findings</th><th>Severity</th><th>Created</th></tr></thead><tbody>" +
      rows.join("") + "</tbody></table>";
  }

  function updateApproval(status) {
    const el = $("#approval");
    if (el) el.hidden = status !== "pending_approval";
    const cancelBtn = $("#cancel");
    if (cancelBtn) cancelBtn.disabled = status === "pending_approval";
  }

  function renderAnalysis(a) {
    const el = $("#rca");
    if (!el) return;
    if (!a) {
      el.innerHTML = '<p class="muted">No analysis yet.</p>';
      return;
    }
    el.innerHTML =
      "<p>" + badge(a.kind) +
      " &nbsp; Step: " + esc(a.step_id) +
      "<br>Root cause: " + esc(a.root_cause) + "</p>" +
      (a.detail ? '<pre class="logbox">' + esc(a.detail) + "</pre>" : "") +
      (a.suggested_fix ? '<p>Suggested fix: ' + esc(a.suggested_fix) + "</p>" : "") +
      (a.command ? '<p class="muted">Command: ' + esc(a.command) + "</p>" : "") +
      (a.log_excerpt ? '<pre class="logbox">' + esc(a.log_excerpt) + "</pre>" : "");
  }

  async function selectStep(step) {
    if (logTimer) { clearInterval(logTimer); logTimer = null; }
    currentStep = step;
    lastSeq = 0;
    $("#log-step").textContent = "Logs for step: " + step;
    $("#logs").textContent = "";
    document.querySelectorAll(".step-row").forEach((tr) => {
      tr.classList.toggle("active", tr.dataset.step === step);
    });
    await appendLogs();
    logTimer = setInterval(appendLogs, 1500);
  }

  async function appendLogs() {
    if (!currentStep) return;
    try {
      const id = document.body.dataset.run;
      const data = await getJSON(
        "/api/runs/" + id + "/logs?step=" + encodeURIComponent(currentStep) +
        "&after=" + lastSeq + "&limit=500"
      );
      const logs = data.logs || [];
      if (!logs.length) return;
      const box = $("#logs");
      for (const l of logs) { box.textContent += l.line + "\n"; lastSeq = l.seq; }
      box.scrollTop = box.scrollHeight;
    } catch (_) { /* transient fetch errors are ignored */ }
  }

  async function runPage() {
    try {
      const data = await loadRun();
      if (!TERMINAL.includes(data.run.status)) {
        statusTimer = setInterval(async () => {
          try {
            const d2 = await loadRun();
            if (TERMINAL.includes(d2.run.status)) stopTimers();
          } catch (_) { /* ignore */ }
        }, 2000);
      }
      if (data.steps.length) selectStep(data.steps[0].step_id);
    } catch (e) {
      $("#run-info").innerHTML = '<p class="error">Failed to load: ' + esc(e.message) + "</p>";
    }
    const cancelBtn = $("#cancel");
    if (cancelBtn) {
      cancelBtn.addEventListener("click", async () => {
        const id = document.body.dataset.run;
        const res = await postJSON("/api/runs/" + id + "/cancel", {});
        if (res.status === 200) { location.reload(); }
        else {
          window.alert("Cancel failed: " +
            ((res.json && res.json.error) || "HTTP " + res.status));
        }
      });
    }
    const approveBtn = $("#approve");
    if (approveBtn) {
      approveBtn.addEventListener("click", async () => {
        const id = document.body.dataset.run;
        const res = await postJSON("/api/runs/" + id + "/approve", {});
        if (res.status === 200) { location.reload(); }
        else {
          window.alert("Approve failed: " +
            ((res.json && res.json.error) || "HTTP " + res.status));
        }
      });
    }
    const rejectBtn = $("#reject");
    if (rejectBtn) {
      rejectBtn.addEventListener("click", async () => {
        const id = document.body.dataset.run;
        const res = await postJSON("/api/runs/" + id + "/reject", {});
        if (res.status === 200) { location.reload(); }
        else {
          window.alert("Reject failed: " +
            ((res.json && res.json.error) || "HTTP " + res.status));
        }
      });
    }
  }

  // --- cost page ------------------------------------------------------------
  function renderCostChart(dayData, el) {
    const days = last7Days();
    const byDay = {};
    for (const r of (dayData.rows || [])) {
      if (r.day && r.day !== "unknown") byDay[r.day] = r.cost_usd;
    }
    const values = days.map((d) => byDay[d] || 0);
    // The SVG itself renders the empty state ("No cost in the last 7 days"),
    // so no extra <p> note is appended here.
    el.innerHTML = PHChart.svgCostBars(days, values);
  }

  async function costPage() {
    const q = new URLSearchParams(location.search);
    const by = q.get("by") || "pr";
    const source = q.get("source") || "";
    const costEl = $("#cost");
    const totalEl = $("#cost-total");
    const chartEl = $("#cost-chart");
    try {
      const [data, dayData] = await Promise.all([
        getJSON("/api/cost?by=" + by + (source ? "&source=" + source : "")),
        getJSON("/api/cost?by=day"),
      ]);
      const rows = data.rows || [];
      if (!rows.length) {
        costEl.innerHTML =
          '<p class="muted">No cost records yet. The agent appends to the shared ledger (FLOWSTALLION_COST_LEDGER).</p>';
      } else {
        const keyLabel = by === "team" ? "Team" : by === "day" ? "Day" : "PR";
        costEl.innerHTML =
          "<table><thead><tr><th>" + keyLabel + "</th><th>Records</th>" +
          "<th>Prompt tokens</th><th>Completion tokens</th><th>Total tokens</th>" +
          "<th>Cost (USD)</th></tr></thead><tbody>" +
          rows.map((r) =>
            "<tr><td>" + esc(r[by]) + "</td><td>" + r.records + "</td>" +
            "<td>" + r.prompt_tokens + "</td><td>" + r.completion_tokens + "</td>" +
            "<td>" + r.total_tokens + "</td><td>" + fmtMoney(r.cost_usd) + "</td></tr>"
          ).join("") + "</tbody></table>";
      }
      const t = data.total;
      if (t && t.records) {
        totalEl.textContent =
          "Total (" + t.records + " records): " + t.total_tokens +
          " tokens, " + fmtMoney(t.cost_usd) + (source ? " · " + source : "");
      } else {
        totalEl.textContent = "";
      }
      if (chartEl) renderCostChart(dayData, chartEl);
    } catch (e) {
      costEl.innerHTML = '<p class="error">Failed to load: ' + esc(e.message) + "</p>";
      if (chartEl) chartEl.innerHTML = '<p class="muted">No cost data.</p>';
    }
  }

  // --- audit page ------------------------------------------------------------
  const AUDIT_PAGE = 50;
  const auditState = { after: 0, count: 0 };

  function auditParams(after) {
    const p = new URLSearchParams();
    p.set("limit", String(AUDIT_PAGE));
    const action = $("#f-action").value;
    const actor = $("#f-actor").value.trim();
    const range = Number($("#f-range").value) || 0;
    if (action) p.set("action", action);
    if (actor) p.set("actor", actor);
    if (range > 0) p.set("since", new Date(Date.now() - range * 1000).toISOString());
    if (after > 0) p.set("after", String(after));
    return p;
  }

  function trunc(s, n) {
    s = String(s == null ? "" : s);
    return s.length > n ? s.slice(0, n - 1) + "…" : s;
  }

  function auditRows(rows) {
    return rows.map((e) =>
      "<tr>" +
      '<td title="' + esc(e.ts || "") + '">' + esc(fmtRel(e.ts)) + "</td>" +
      "<td>" + esc(e.actor) + "</td>" +
      "<td>" + esc(e.action) + "</td>" +
      "<td>" + esc(e.target || "") + "</td>" +
      "<td>" + outcomeBadge(e.outcome) + "</td>" +
      '<td class="trunc" title="' + esc(e.detail || "") + '">' + esc(trunc(e.detail, 60)) + "</td>" +
      "<td>" + esc(e.src || "") + "</td>" +
      "</tr>"
    ).join("");
  }

  async function loadAudit(append) {
    const el = $("#audit");
    const more = $("#audit-more");
    const note = $("#audit-note");
    if (more) more.hidden = true;
    let data;
    try {
      data = await getJSON("/api/audit?" + auditParams(append ? auditState.after : 0).toString());
    } catch (e) {
      if (!append) {
        el.innerHTML = '<p class="error">Failed to load: ' + esc(e.message) + "</p>";
      } else if (more) {
        more.hidden = false;
      }
      return;
    }
    const rows = data.events || [];
    if (!append) {
      auditState.count = 0;
      if (!rows.length) {
        el.innerHTML = '<p class="muted">No audit events match the filters.</p>';
        if (note) note.textContent = "";
        return;
      }
      el.innerHTML =
        '<table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th>' +
        "<th>Outcome</th><th>Detail</th><th>Src</th></tr></thead><tbody></tbody></table>";
    }
    if (rows.length) {
      el.querySelector("tbody").insertAdjacentHTML("beforeend", auditRows(rows));
      auditState.after = rows[rows.length - 1].id;
      auditState.count += rows.length;
    }
    if (note) note.textContent = auditState.count + " event(s) shown";
    if (more) more.hidden = rows.length < AUDIT_PAGE;
  }

  function auditPage() {
    const form = $("#audit-filters");
    if (form) form.addEventListener("submit", (e) => {
      e.preventDefault();
      auditState.after = 0;
      loadAudit(false);
    });
    const more = $("#audit-more");
    if (more) more.addEventListener("click", () => loadAudit(true));
    loadAudit(false);
  }

  // --- settings page -----------------------------------------------------------
  async function loadUsers() {
    const el = $("#users");
    let data;
    try {
      data = await getJSON("/api/users");
    } catch (e) {
      el.innerHTML = '<p class="error">Failed to load users: ' + esc(e.message) + "</p>";
      return;
    }
    const users = data.users || [];
    if (!users.length) {
      el.innerHTML = '<p class="muted">No users.</p>';
      return;
    }
    el.innerHTML =
      '<table><thead><tr><th>Username</th><th>Role</th><th>Created</th><th></th></tr></thead><tbody>' +
      users.map((u) =>
        "<tr><td>" + esc(u.username) + "</td>" +
        "<td>" + esc(u.role) + "</td>" +
        '<td title="' + esc(u.created_at || "") + '">' + esc(fmtRel(u.created_at)) + "</td>" +
        '<td><button class="btn danger tsm" data-del-user="' + esc(u.username) + '">Delete</button></td></tr>'
      ).join("") + "</tbody></table>";
    el.querySelectorAll("[data-del-user]").forEach((b) => {
      b.addEventListener("click", async () => {
        const name = b.dataset.delUser;
        if (!confirm('Delete user "' + name + '"? This cannot be undone.')) return;
        b.disabled = true;
        const res = await delJSON("/api/users/" + encodeURIComponent(name));
        if (res.status === 204 || res.status === 200) {
          setMsg("#user-msg", "User " + name + " deleted.");
          loadUsers();
        } else {
          b.disabled = false;
          setMsg("#user-msg", "Delete failed: " + errMsg(res), true);
        }
      });
    });
  }

  function bindUserForm() {
    const form = $("#user-form");
    if (!form) return;
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const res = await postJSON("/api/users", {
        username: $("#user-name").value.trim(),
        password: $("#user-password").value,
        role: $("#user-role").value,
      });
      if (res.status === 201) {
        form.reset();
        setMsg("#user-msg", "User created.");
        loadUsers();
      } else {
        setMsg("#user-msg", "Create failed: " + errMsg(res), true);
      }
    });
  }

  async function loadSecrets() {
    const el = $("#secrets");
    let data;
    try {
      data = await getJSON("/api/secrets");
    } catch (e) {
      el.innerHTML = '<p class="error">Failed to load secrets: ' + esc(e.message) + "</p>";
      return;
    }
    const secs = data.secrets || [];
    if (!secs.length) {
      el.innerHTML = '<p class="muted">No secrets stored.</p>';
      return;
    }
    el.innerHTML =
      '<table><thead><tr><th>Name</th><th>Created</th><th>Updated</th><th></th></tr></thead><tbody>' +
      secs.map((s) =>
        "<tr><td>" + esc(s.name) + "</td>" +
        '<td title="' + esc(s.created_at || "") + '">' + esc(fmtRel(s.created_at)) + "</td>" +
        '<td title="' + esc(s.updated_at || "") + '">' + esc(fmtRel(s.updated_at)) + "</td>" +
        '<td><button class="btn danger tsm" data-del-secret="' + esc(s.name) + '">Delete</button></td></tr>'
      ).join("") + "</tbody></table>";
    el.querySelectorAll("[data-del-secret]").forEach((b) => {
      b.addEventListener("click", async () => {
        const name = b.dataset.delSecret;
        if (!confirm('Delete secret "' + name + '"?')) return;
        b.disabled = true;
        const res = await delJSON("/api/secrets/" + encodeURIComponent(name));
        if (res.status === 204 || res.status === 200) {
          setMsg("#secret-msg", "Secret " + name + " deleted.");
          loadSecrets();
        } else {
          b.disabled = false;
          setMsg("#secret-msg", "Delete failed: " + errMsg(res), true);
        }
      });
    });
  }

  function bindSecretForm() {
    const form = $("#secret-form");
    if (!form) return;
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const name = $("#secret-name").value.trim();
      const value = $("#secret-value").value;
      const res = await postJSON("/api/secrets", { name: name, value: value });
      if (res.status === 200) {
        $("#secret-value").value = "";
        setMsg("#secret-msg", name + " saved (value is stored encrypted and never shown again).");
        loadSecrets();
      } else {
        setMsg("#secret-msg", "Save failed: " + errMsg(res), true);
      }
    });
  }

  function settingsPage() {
    loadUsers();
    bindUserForm();
    loadSecrets();
    bindSecretForm();
  }

  // Rewrite static template links (brand, nav, back links) so page navigation
  // carries the session token in the "flowstallion" query parameter.
  function rewriteStaticLinks() {
    if (!authOn || !token) return;
    document.querySelectorAll("a[href]").forEach((a) => {
      const href = a.getAttribute("href");
      if (!href || href.startsWith("/static") || href.startsWith("/login")) return;
      if (href.startsWith("http") || href.startsWith("#") || href.includes("flowstallion=")) return;
      a.setAttribute("href", pagePath(href));
    });
  }

  async function initAuth() {
    if (!authOn) { role = "admin"; return; }
    const who = $("#whoami");
    const signout = $("#signout");
    if (!token) { goLogin(); return; }
    try {
      const me = await getJSON("/api/auth/me");
      role = me.role || "viewer";
      if (who) who.textContent = me.username + " (" + me.role + ")";
      if (signout) {
        signout.hidden = false;
        signout.addEventListener("click", async () => {
          try { await postJSON("/api/auth/logout", {}); } catch (_) { /* best effort */ }
          localStorage.removeItem("flowstallion-token");
          location.href = "/login";
        });
      }
    } catch (_) { /* getJSON already redirects on 401 */ }
  }

  (async function boot() {
    await initAuth();
    rewriteStaticLinks();
    if (page === "home") home();
    else if (page === "pipeline") pipelinePage();
    else if (page === "run") runPage();
    else if (page === "cost") costPage();
    else if (page === "audit") auditPage();
    else if (page === "settings") settingsPage();
  })();
})();

/* Yukti dashboard — drill-down spine over the live runtime.
   Fleet aggregate (tiles) → live flow timeline (rate strip + chronological feed) →
   action leaf (grouped by priority). WebSocket streams ProcessResults; everything
   updates live. Clicking a row or action opens the detail drawer with the full
   evidence chain. */
(function () {
  "use strict";
  const P = window.Platinum;

  /* ---------------- Pattern family configuration ----------------
     Loaded from /api/meta at boot (so the server picks the family set for the
     active mode — fleet governance vs agent-breakout). This hardcoded list is
     the fallback if /api/meta is unreachable, so the dashboard never renders
     empty. */
  let PATTERN_FAMILIES = [
    { id: "egress_data_leak",     label: "Egress",      accent: "egress" },
    { id: "change_velocity",      label: "Change",      accent: "change" },
    { id: "retry_amplification",  label: "Retry",       accent: "retry"  },
    { id: "auth_access_anomaly",  label: "Auth",        accent: "auth"   },
    { id: "evidence_shape_drift", label: "Drift",       accent: "drift"  },
  ];

  const TIMELINE_MAX_ROWS = 80;      // cap DOM rows for perf — newest at top
  const RATE_WINDOW_SECONDS = 60;    // last-60s rate strip

  /* ---------------- State ---------------- */
  const state = {
    counts: { flows: 0, evidence: 0, actions: 0 },
    patterns: Object.fromEntries(PATTERN_FAMILIES.map(f => [f.id, 0])),
    actions: new Map(),              // intervention_id -> action obj (from /api/actions/pending)
    flowTypes: new Set(),            // populated from incoming flows
    timelineEvents: [],              // recent ProcessResults — newest first
    fleet: new Map(),                // base-agent -> worst {decision, consequence} for the headline
    patternWindow: {},               // pattern id -> [{agent, ts}] within the trend window
    rateBuckets: [],                 // {ts, decision} entries within RATE_WINDOW_SECONDS
    filter: { flowType: "", decision: "", pattern: "" },
    summary: null,                   // latest /api/fleet/summary snapshot (drives the posture panel)
  };

  const PATTERN_WINDOW_SECONDS = 45; // one tile = distinct agents in this window

  /* ---------------- Fleet tiles ---------------- */
  function renderFleetTiles() {
    const grid = P.must("#fleet-tiles");
    grid.innerHTML = "";

    const tiles = [
      { id: "total-flows",     label: "Total flows",     accent: "flows",    value: state.counts.flows, sub: "cumulative" },
      { id: "evidence",        label: "Evidence",        accent: "evidence", value: state.counts.evidence, sub: "records" },
      { id: "pending-actions", label: "Pending actions", accent: "actions",  value: state.counts.actions, sub: "open" },
    ];

    for (const t of tiles) {
      const tile = P.el(`
        <div class="tile" data-accent="${t.accent}" data-tile-id="${t.id}">
          <div class="tile-label">${t.label}</div>
          <div class="tile-value">${t.value}</div>
          ${t.sub ? `<div class="tile-sub">${t.sub}</div>` : ""}
        </div>
      `);
      grid.appendChild(tile);
    }
    // pattern tiles: clickable doors, value = distinct agents in the window
    for (const f of PATTERN_FAMILIES) {
      const tile = P.el(`
        <div class="tile tile-pattern" data-accent="${f.accent}" data-tile-id="family-${f.id}"
             data-pattern-id="${f.id}" data-level="clear" role="button" tabindex="0"
             title="click to show the ${escapeHtml(f.label)} agents">
          <div class="tile-label">${f.label}</div>
          <div class="tile-value">0</div>
          <div class="tile-sub">no agents</div>
        </div>
      `);
      grid.appendChild(tile);
    }
    renderPatternTiles();
    reflectPatternFilter();
  }

  function bumpTile(tileId, newValue) {
    const tile = document.querySelector(`[data-tile-id="${tileId}"] .tile-value`);
    if (tile) {
      tile.textContent = newValue;
      P.pulse(tile, "tile-pulse");
    }
  }

  /* ---------------- Pattern tiles: distinct agents + trend ---------------- */
  const TREND = { up: "↑ rising", flat: "→ steady", down: "↓ easing" };
  function patternStats(id) {
    const now = Date.now() / 1000;
    const W = PATTERN_WINDOW_SECONDS;
    const events = (state.patternWindow[id] || []).filter(e => e.ts >= now - 2 * W);
    state.patternWindow[id] = events;                       // prune as we go
    const cur = new Set();
    const prev = new Set();
    for (const e of events) {
      if (e.ts >= now - W) cur.add(e.agent);
      else prev.add(e.agent);
    }
    const distinct = cur.size;
    let trend = "flat";
    if (distinct > prev.size) trend = "up";
    else if (distinct < prev.size) trend = "down";
    const level = distinct === 0 ? "clear" : (trend === "up" ? "rising" : "active");
    return { distinct, trend, level };
  }
  function renderPatternTiles() {
    for (const f of PATTERN_FAMILIES) {
      const tile = document.querySelector(`[data-pattern-id="${f.id}"]`);
      if (!tile) continue;
      const { distinct, trend, level } = patternStats(f.id);
      const valueEl = tile.querySelector(".tile-value");
      const subEl = tile.querySelector(".tile-sub");
      if (valueEl && valueEl.textContent !== String(distinct)) {
        valueEl.textContent = distinct;
        P.pulse(valueEl, "tile-pulse");
      }
      if (subEl) {
        subEl.textContent = distinct === 0
          ? "no agents"
          : `${distinct === 1 ? "1 agent" : distinct + " agents"} · ${TREND[trend]}`;
      }
      tile.setAttribute("data-level", level);
    }
  }

  /* ---------------- Rate strip (last 60s) ---------------- */
  function pruneRateBuckets() {
    const cutoff = Date.now() / 1000 - RATE_WINDOW_SECONDS;
    state.rateBuckets = state.rateBuckets.filter(e => e.ts >= cutoff);
  }

  function renderRateStrip() {
    pruneRateBuckets();
    const counts = { allow: 0, monitor: 0, gate: 0, deny: 0 };
    for (const e of state.rateBuckets) {
      if (counts[e.decision] !== undefined) counts[e.decision] += 1;
    }
    P.must("#rate-allow").textContent = counts.allow;
    P.must("#rate-monitor").textContent = counts.monitor;
    P.must("#rate-gate").textContent = counts.gate;
    P.must("#rate-deny").textContent = counts.deny;
    P.must("#rate-total").textContent = state.rateBuckets.length;
  }

  /* ---------------- Timeline ---------------- */
  function passesFilter(ev) {
    if (state.filter.flowType && ev.flowType !== state.filter.flowType) return false;
    if (state.filter.decision && ev.decision !== state.filter.decision) return false;
    if (state.filter.pattern
        && !(ev.patterns || []).some(p => p.name === state.filter.pattern)) return false;
    return true;
  }

  function togglePatternFilter(id) {
    state.filter.pattern = state.filter.pattern === id ? "" : id;
    reflectPatternFilter();
    renderTimeline();
  }
  function reflectPatternFilter() {
    for (const f of PATTERN_FAMILIES) {
      const tile = document.querySelector(`[data-pattern-id="${f.id}"]`);
      if (tile) tile.classList.toggle("tile-active", state.filter.pattern === f.id);
    }
    const chip = document.getElementById("timeline-filter-chip");
    if (chip) {
      if (state.filter.pattern) {
        chip.style.display = "";
        chip.innerHTML = `showing <b>${escapeHtml(state.filter.pattern)}</b> agents <span class="chip-x">✕ clear</span>`;
      } else {
        chip.style.display = "none";
        chip.innerHTML = "";
      }
    }
  }

  function renderTimeline() {
    const tl = P.must("#timeline");
    const visible = state.timelineEvents.filter(passesFilter);
    if (visible.length === 0) {
      tl.innerHTML = `<p class="empty-hint">Waiting for flows…</p>`;
      return;
    }
    tl.innerHTML = "";
    for (const ev of visible) {
      tl.appendChild(buildTimelineRow(ev, false));
    }
  }

  function buildTimelineRow(ev, isNew) {
    const patternText = ev.patterns.length
      ? ev.patterns.map(p => p.name).join(", ")
      : "";
    // Plain language first: the agent and what it actually did. The raw
    // pattern-ids move to the hover title — a human reads the consequence, an
    // engineer can still see which predicates fired.
    const headline = ev.consequence
      ? escapeHtml(ev.consequence)
      : (patternText ? escapeHtml(patternText) : "stayed in envelope");
    const agentText = ev.agent ? escapeHtml(ev.agent) : escapeHtml(ev.flowType);
    const titleAttr = patternText ? ` title="patterns: ${escapeHtml(patternText)}"` : "";
    const row = P.el(`
      <article class="timeline-row${isNew ? " row-new" : ""}" role="listitem"
               data-decision="${ev.decision}" data-flow-id="${ev.flowId}"${titleAttr}>
        <span class="timeline-time">${P.formatTime(ev.ts)}</span>
        <div class="timeline-mid">
          <span class="timeline-agent">${agentText}<span class="timeline-flow"> · ${escapeHtml(ev.flowType)}</span></span>
          <span class="timeline-consequence">${headline}</span>
        </div>
        <div class="timeline-end">
          <span class="decision-badge" data-decision="${ev.decision}">${ev.decision}</span>
        </div>
      </article>
    `);
    return row;
  }

  /* ---------------- Fleet headline ---------------- */
  // Track the worst decision + consequence per base agent (loop suffix stripped)
  // so the headline reads a stable "N of M runs broke containment · worst: …".
  // decision values arrive lowercase (StrEnum value: "deny", "gate", …)
  const DECISION_RANK = { deny: 3, gate: 2, monitor: 1, allow: 0 };
  function baseAgent(ev) {
    // The payload agent IS the stable identity (fraud-scorer, kri-monitor/RE-01,
    // network-recon…) — use it verbatim. Stripping trailing digits here would
    // collapse distinct ids like RE-01/RE-02/RE-03 into one, which showed up as
    // "1 of 1 indicators" and "1 agent" on every tile. Only the flowId fallback
    // (a trace id with simulator loop/step suffixes) needs those stripped.
    if (ev.agent) return ev.agent;
    return (ev.flowId || "")
      .replace(/-\d+-loop\d+$/, "")
      .replace(/-l\d+$/, "")
      .replace(/-\d+$/, "");
  }
  function updateFleet(ev) {
    const key = baseAgent(ev);
    if (!key) return;
    const rank = DECISION_RANK[ev.decision] ?? 0;
    const prev = state.fleet.get(key);
    if (!prev || rank >= prev.rank) {
      state.fleet.set(key, {
        rank, decision: ev.decision, flow: ev.flowType,
        consequence: ev.consequence || "", ts: ev.ts,
      });
    }
    renderHeadline();
  }
  function renderHeadline() {
    const el = document.getElementById("fleet-headline");
    if (!el) return;
    const runs = Array.from(state.fleet.values());
    const total = runs.length;
    const broke = runs.filter(r => r.rank >= 2).length;   // GATE or DENY
    const worst = runs
      .filter(r => r.rank >= 2)
      .sort((a, b) => b.rank - a.rank || b.ts - a.ts)[0];
    if (total === 0) { el.innerHTML = ""; return; }
    const vocab = state.headlineVocab || { unit: "agent runs", breach: "broke containment", clean: "the fleet is inside its envelopes" };
    if (broke === 0) {
      el.className = "fleet-headline clean";
      el.innerHTML = `<b>${total}</b> ${vocab.unit} observed · <b>0</b> ${vocab.breach} — ${vocab.clean}.`;
      return;
    }
    el.className = "fleet-headline alert";
    const worstAgent = worst ? Array.from(state.fleet.entries()).find(([, v]) => v === worst)?.[0] : "";
    const worstLine = worst
      ? ` · worst: <b>${escapeHtml(worstAgent)}</b> — ${escapeHtml(worst.consequence || worst.flow)} <span class="hd-tier" data-decision="${worst.decision}">${worst.decision === "deny" ? "CRITICAL" : "HIGH"}</span>`
      : "";
    el.innerHTML = `<b>${broke}</b> of <b>${total}</b> ${vocab.unit} ${vocab.breach}${worstLine}`;
  }

  function prependTimelineEvent(ev) {
    state.timelineEvents.unshift(ev);
    if (state.timelineEvents.length > TIMELINE_MAX_ROWS) {
      state.timelineEvents.length = TIMELINE_MAX_ROWS;
    }
    if (!passesFilter(ev)) return;

    const tl = P.must("#timeline");
    const hint = tl.querySelector(".empty-hint");
    if (hint) tl.innerHTML = "";

    tl.prepend(buildTimelineRow(ev, true));
    while (tl.children.length > TIMELINE_MAX_ROWS) {
      tl.removeChild(tl.lastChild);
    }
  }

  function updateFlowTypeFilter() {
    const sel = P.must("#filter-type");
    const current = sel.value;
    const existing = new Set(Array.from(sel.options).map(o => o.value));
    for (const ft of state.flowTypes) {
      if (!existing.has(ft)) {
        const opt = document.createElement("option");
        opt.value = ft; opt.textContent = ft;
        sel.appendChild(opt);
      }
    }
    if (current && state.flowTypes.has(current)) sel.value = current;
  }

  /* ---------------- Action panel (grouped by priority) ---------------- */
  const PRIORITY_ORDER = ["critical", "high", "medium", "low"];

  function renderActions() {
    const list = P.must("#action-list");
    const items = Array.from(state.actions.values());

    P.must("#actions-count").textContent = items.length;

    if (items.length === 0) {
      list.innerHTML = `<p class="empty-hint">No pending interventions. The fleet is governing itself.</p>`;
      return;
    }

    // Group by priority.
    const groups = Object.fromEntries(PRIORITY_ORDER.map(p => [p, []]));
    for (const item of items) {
      const p = (item.priority || "low").toLowerCase();
      if (groups[p]) groups[p].push(item);
    }
    for (const arr of Object.values(groups)) {
      arr.sort((a, b) => a.created_at - b.created_at);
    }

    list.innerHTML = "";
    const nowSec = Date.now() / 1000;
    for (const priority of PRIORITY_ORDER) {
      const arr = groups[priority];
      if (!arr.length) continue;
      const group = P.el(`
        <div class="action-group" data-priority="${priority}">
          <div class="action-group-header">
            <span>${priority}</span>
            <span class="action-group-count">${arr.length}</span>
          </div>
        </div>
      `);
      for (const item of arr.slice(0, 20)) {
        group.appendChild(buildActionItem(item, priority, nowSec));
      }
      list.appendChild(group);
    }
  }

  function buildActionItem(item, priority, nowSec) {
    const ageText = P.timeAgo(item.created_at, nowSec);
    // Human first: which agent, what it did. Fall back to the intervention type
    // for interventions that predate the human-summary payload.
    const agent = item.payload?.agent;
    const flow = item.payload?.flow;
    const consequence = item.payload?.consequence;
    const title = agent
      ? `${escapeHtml(agent)}${flow ? `<span class="action-flow"> · ${escapeHtml(flow)}</span>` : ""}`
      : escapeHtml((item.type || "").replace(/_/g, " "));
    const body = consequence
      ? escapeHtml(consequence)
      : escapeHtml(item.flow_id || "");

    return P.el(`
      <article class="action-item" data-intervention-id="${item.intervention_id}">
        <span class="action-pri" data-priority="${priority}">${priority}</span>
        <div class="action-meta">
          <span class="action-title">${title}</span>
          <span class="action-trace">${body}</span>
          <span class="action-age">${ageText}</span>
        </div>
      </article>
    `);
  }

  /* ---------------- Detail drawer ---------------- */
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, ch => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[ch]));
  }

  function openDetail(title, bodyHtml) {
    P.must("#detail-title").textContent = title;
    const body = P.must("#detail-body");
    body.innerHTML = typeof bodyHtml === "string" ? bodyHtml : "";
    P.must("#detail-zone").removeAttribute("hidden");
    P.must("#detail-zone").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function closeDetail() {
    P.must("#detail-zone").setAttribute("hidden", "");
  }

  async function showFlowDetail(flowId) {
    try {
      const resp = await fetch(`/api/flows/${encodeURIComponent(flowId)}`);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      openDetail(`flow · ${flowId}`, renderFlowDetailBody(data));
    } catch (e) {
      openDetail(`flow · ${flowId}`, `<p class="empty-hint">${escapeHtml(String(e))}</p>`);
    }
  }

  function renderFlowDetailBody(data) {
    const kv = `
      <div class="kv"><span class="kv-key">flow_type</span><span class="kv-val">${escapeHtml(data.flow_type)}</span></div>
      <div class="kv"><span class="kv-key">state</span><span class="kv-val">${escapeHtml(data.state)}</span></div>
      <div class="kv"><span class="kv-key">steps</span><span class="kv-val">${data.step_count}</span></div>
      <div class="kv"><span class="kv-key">evidence</span><span class="kv-val">${data.evidence_count}</span></div>
      <div class="kv"><span class="kv-key">patterns</span><span class="kv-val">${escapeHtml((data.pattern_matches || []).join(", ") || "—")}</span></div>
    `;
    const chain = (data.evidence_chain || []).map(r => `
      <div class="evidence-card">
        <span class="evidence-tier" data-tier="${escapeHtml(r.tier)}">${escapeHtml(r.tier)}</span>
        <div class="evidence-sha">${escapeHtml(r.sha256)}</div>
        <pre class="evidence-payload">${escapeHtml(P.formatJson(r.payload))}</pre>
      </div>
    `).join("");
    return `${kv}<div class="evidence-chain">${chain}</div>`;
  }

  async function showActionDetail(interventionId) {
    try {
      const resp = await fetch(`/api/actions/${encodeURIComponent(interventionId)}`);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      openDetail(`action · ${interventionId}`, renderActionDetailBody(data));
    } catch (e) {
      openDetail(`action · ${interventionId}`, `<p class="empty-hint">${escapeHtml(String(e))}</p>`);
    }
  }

  function renderActionDetailBody(data) {
    const finalDecision = data.payload?.decision || "";
    const { policies, decisive } = P.parseRationale(data.payload?.rationale, finalDecision);
    const policyRows = policies.map(p => {
      const isDecisive = decisive && p.name === decisive.name && p.decision === decisive.decision;
      return `<div class="kv"><span class="kv-key">${escapeHtml(p.name)}</span><span class="kv-val">${
        isDecisive ? `<strong>${escapeHtml(p.decision)}</strong> ← decisive` : escapeHtml(p.decision)
      }</span></div>`;
    }).join("");

    const kv = `
      <div class="kv"><span class="kv-key">type</span><span class="kv-val">${escapeHtml(data.type)}</span></div>
      <div class="kv"><span class="kv-key">priority</span><span class="kv-val"><span class="action-pri" data-priority="${data.priority}">${data.priority}</span></span></div>
      <div class="kv"><span class="kv-key">flow</span><span class="kv-val">${escapeHtml(data.flow_id)}</span></div>
      <div class="kv"><span class="kv-key">created</span><span class="kv-val">${P.formatTime(data.created_at)}</span></div>
      <div class="kv"><span class="kv-key">sla deadline</span><span class="kv-val">${P.formatTime(data.sla_deadline)}</span></div>
      <div class="kv"><span class="kv-key">final decision</span><span class="kv-val"><span class="decision-badge" data-decision="${finalDecision}">${escapeHtml(finalDecision)}</span></span></div>
      ${policyRows}
    `;
    const chain = (data.evidence_lineage || []).map(r => `
      <div class="evidence-card">
        <span class="evidence-tier" data-tier="${escapeHtml(r.tier)}">${escapeHtml(r.tier)}</span>
        <div class="evidence-sha">${P.shortSha(r.sha256)}</div>
        <pre class="evidence-payload">${escapeHtml(P.formatJson(r.payload))}</pre>
      </div>
    `).join("");
    return `${kv}<div class="evidence-chain">${chain}</div>`;
  }

  /* ---------------- WebSocket ---------------- */
  function setStatus(state_, text) {
    P.must("#status-dot").dataset.state = state_;
    P.must("#status-text").textContent = text;
  }

  function handleProcessResult(result) {
    // Tile bumps
    state.counts.flows += 1;
    state.counts.evidence += (result.evidence_chain || []).length;
    bumpTile("total-flows", state.counts.flows);
    bumpTile("evidence", state.counts.evidence);

    // Build the timeline event
    const obs = result.observation || {};
    const extra = obs.extra || {};
    const flowType = extra.flow_type || "default";
    state.flowTypes.add(flowType);

    const ev = {
      flowId: result.trace_id,
      flowType,
      agent: obs.payload?.agent || "",
      consequence: obs.payload?.consequence || "",
      decision: result.decision,
      ts: obs.timestamp || (Date.now() / 1000),
      patterns: (result.pattern_matches || []).map(m => ({
        name: m.pattern_name, confidence: m.confidence,
      })),
    };
    updateFleet(ev);

    // record each fired pattern into its rolling window, keyed by the base
    // agent — the tile counts DISTINCT AGENTS in the window, not cumulative
    // replays (which only ever climb and mean nothing).
    for (const m of (result.pattern_matches || [])) {
      const key = m.pattern_name;
      if (state.patterns[key] === undefined) continue;
      (state.patternWindow[key] || (state.patternWindow[key] = []))
        .push({ agent: baseAgent(ev), ts: ev.ts });
    }
    renderPatternTiles();

    prependTimelineEvent(ev);
    updateFlowTypeFilter();

    // Rate strip
    state.rateBuckets.push({ ts: ev.ts, decision: ev.decision });
    renderRateStrip();

    // Actions: only refetch when a new intervention was created
    if (result.intervention_id) {
      fetchPendingActions();
    }
  }

  async function fetchPendingActions() {
    try {
      const resp = await fetch("/api/actions/pending?limit=200");
      const data = await resp.json();
      state.actions = new Map((data.items || []).map(it => [it.intervention_id, it]));
      state.counts.actions = data.total;
      bumpTile("pending-actions", state.counts.actions);
      renderActions();
    } catch (e) {
      console.error("fetchPendingActions failed", e);
    }
  }

  async function fetchFleetSummary() {
    try {
      const resp = await fetch("/api/fleet/summary");
      const s = await resp.json();
      state.summary = s;
      state.counts.flows = s.total_flows;
      state.counts.evidence = s.evidence_records;
      state.counts.actions = s.pending_actions;
      for (const f of PATTERN_FAMILIES) {
        state.patterns[f.id] = (s.pattern_matches && s.pattern_matches[f.id]) || 0;
      }
      renderPosture(s);
      renderFleetTiles();
    } catch (e) {
      console.error("fetchFleetSummary failed", e);
    }
  }

  /* ---------------- Posture — the analytical hero, from the summary API ----------------
     Rendered from /api/fleet/summary (cumulative, server-computed) on boot and every
     few seconds, so it is always populated — not dependent on a live WebSocket stream. */
  const _DEC_ORDER = [["allow", "Allow"], ["monitor", "Monitor"], ["gate", "Gate"], ["deny", "Deny"]];

  function renderPosture(s) {
    const el = document.getElementById("posture");
    if (!el || !s) return;
    const dec = s.decisions || {};
    const total = _DEC_ORDER.reduce((a, [k]) => a + (dec[k] || 0), 0) || 1;
    const segs = _DEC_ORDER
      .filter(([k]) => dec[k])
      .map(([k]) => `<div class="dist-seg" data-decision="${k}" style="width:${(dec[k] / total * 100).toFixed(1)}%" title="${k}: ${dec[k]}"></div>`)
      .join("");
    const legend = _DEC_ORDER
      .map(([k, label]) => `<span class="dl"><i data-decision="${k}"></i>${label} <b>${dec[k] || 0}</b></span>`)
      .join("");
    const stats = [
      ["", s.total_flows || 0, "governed"],
      ["deny", dec.deny || 0, "contained"],
      ["gate", s.pending_actions || 0, "awaiting human"],
      ["allow", dec.allow || 0, "clean"],
    ]
      .map(([cls, n, label]) => `<div class="pstat ${cls}"><b>${n}</b><span>${label}</span></div>`)
      .join("");
    const flows = Object.entries(s.by_flow_type || {}).sort((a, b) => b[1] - a[1]).slice(0, 6);
    const maxFlow = Math.max(1, ...flows.map(([, n]) => n));
    const flowRows = flows
      .map(([name, n]) => `<div class="flow-row"><span class="flow-name">${escapeHtml(name)}</span><span class="flow-bar"><i style="width:${(n / maxFlow * 100).toFixed(0)}%"></i></span><span class="flow-n">${n}</span></div>`)
      .join("") || '<div class="empty-hint">no flows yet</div>';
    el.innerHTML =
      '<div class="posture-main">' +
        '<div class="posture-block"><div class="posture-label">governance outcome</div>' +
        `<div class="dist-bar">${segs}</div><div class="dist-legend">${legend}</div></div>` +
        `<div class="posture-stats">${stats}</div>` +
      '</div>' +
      '<div class="posture-block posture-flows"><div class="posture-label">activity by flow</div>' +
      `<div class="flow-bars">${flowRows}</div></div>`;
  }

  function connectWebSocket() {
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    const url = `${proto}//${location.host}/ws/stream`;
    setStatus("connecting", "connecting…");
    const ws = new WebSocket(url);

    ws.onopen = () => setStatus("live", "live");
    ws.onclose = () => {
      setStatus("disconnected", "disconnected — retrying");
      setTimeout(connectWebSocket, 2000);
    };
    ws.onerror = (e) => console.error("ws error", e);
    ws.onmessage = (msg) => {
      try {
        const env = JSON.parse(msg.data);
        if (env.event === "process_result") handleProcessResult(env.data);
        else if (env.event === "mode_changed") resetForMode();
      } catch (e) {
        console.error("bad ws message", e);
      }
    };
  }

  /* ---------------- Wire up + boot ---------------- */
  function wireEvents() {
    P.delegate(P.must("#action-list"), ".action-item", (el) => {
      const id = el.dataset.interventionId;
      if (id) showActionDetail(id);
    });
    P.delegate(P.must("#timeline"), ".timeline-row", (el) => {
      const id = el.dataset.flowId;
      if (id) showFlowDetail(id);
    });
    P.must("#detail-close").addEventListener("click", closeDetail);

    P.must("#filter-type").addEventListener("change", (ev) => {
      state.filter.flowType = ev.target.value;
      renderTimeline();
    });
    P.must("#filter-decision").addEventListener("change", (ev) => {
      state.filter.decision = ev.target.value;
      renderTimeline();
    });

    // Switch governance domain live — the server swaps the runtime and
    // broadcasts mode_changed, which resets every connected dashboard.
    const modeSel = document.getElementById("mode-select");
    if (modeSel) modeSel.addEventListener("change", async (ev) => {
      const mode = ev.target.value;
      modeSel.disabled = true;
      try {
        await fetch("/api/mode", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ mode }),
        });
      } finally {
        modeSel.disabled = false;
      }
    });

    // Click a pattern tile to drill into its agents; click again to clear.
    P.delegate(P.must("#fleet-tiles"), ".tile-pattern", (el) => {
      const id = el.getAttribute("data-pattern-id");
      if (id) togglePatternFilter(id);
    });
    P.must("#fleet-tiles").addEventListener("keydown", (ev) => {
      if (ev.key !== "Enter" && ev.key !== " ") return;
      const el = ev.target.closest && ev.target.closest(".tile-pattern");
      if (el) { ev.preventDefault(); togglePatternFilter(el.getAttribute("data-pattern-id")); }
    });
    const chip = document.getElementById("timeline-filter-chip");
    if (chip) chip.addEventListener("click", () => togglePatternFilter(state.filter.pattern));

    // Refresh ages + recompute the windowed pattern tiles once per second so the
    // distinct-agent counts and trends age out honestly.
    setInterval(() => {
      if (state.actions.size > 0) renderActions();
      renderRateStrip();
      renderPatternTiles();
    }, 1000);

    // Refresh the posture panel from the summary API so the analysis stays current
    // (and populated) even between WebSocket events.
    setInterval(fetchFleetSummary, 5000);
  }

  async function loadMeta() {
    try {
      const resp = await fetch("/api/meta");
      if (!resp.ok) return;
      const meta = await resp.json();
      if (Array.isArray(meta.pattern_families) && meta.pattern_families.length) {
        PATTERN_FAMILIES = meta.pattern_families;
        state.patterns = Object.fromEntries(PATTERN_FAMILIES.map(f => [f.id, 0]));
      }
      if (meta.headline) state.headlineVocab = meta.headline;
      if (Array.isArray(meta.modes)) {
        const sel = document.getElementById("mode-select");
        if (sel && !sel.options.length) {
          for (const m of meta.modes) {
            const opt = document.createElement("option");
            opt.value = m.id; opt.textContent = m.label;
            sel.appendChild(opt);
          }
        }
        if (sel && meta.mode) sel.value = meta.mode;
      }
      if (meta.mode) {
        const MODE_SUBS = {
          breakout: "agent breakout — live fleet",
          reliability: "sre reliability — live fleet",
          "data-leak": "data-leak prevention — live fleet",
          risk: "risk engineering — KRI catalog",
          cyber: "cyber governance — engagement",
        };
        const sub = document.querySelector(".app-header .brand-tag");
        if (sub) sub.textContent = MODE_SUBS[meta.mode] || "patterns × flows × decisions";
      }
    } catch (_e) {
      /* keep the hardcoded fallback families */
    }
  }

  // Switch the live governance domain: clear every domain-specific bit of state
  // (the new runtime has fresh stores) and re-render from the new /api/meta.
  async function resetForMode() {
    state.counts = { flows: 0, evidence: 0, actions: 0 };
    state.actions = new Map();
    state.flowTypes = new Set();
    state.timelineEvents = [];
    state.fleet = new Map();
    state.patternWindow = {};
    state.rateBuckets = [];
    state.filter = { flowType: "", decision: "", pattern: "" };
    await loadMeta();
    state.patterns = Object.fromEntries(PATTERN_FAMILIES.map(f => [f.id, 0]));
    renderFleetTiles();
    updateFlowTypeFilter();
    const dsel = document.getElementById("filter-decision");
    if (dsel) dsel.value = "";
    renderTimeline();
    renderRateStrip();
    renderHeadline();
    await fetchFleetSummary();
    await fetchPendingActions();
  }

  async function boot() {
    await loadMeta();
    renderFleetTiles();
    renderTimeline();
    wireEvents();
    await fetchFleetSummary();
    await fetchPendingActions();
    connectWebSocket();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();

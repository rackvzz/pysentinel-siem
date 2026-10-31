// pysentinel-siem dashboard: polls the JSON API and renders stat tiles,
// two small inline-SVG charts, and the alerts/events tables. No chart
// library -- just DOM/SVG built directly, per the project's "this is my
// own code" goal.

const SVG_NS = "http://www.w3.org/2000/svg";
const POLL_INTERVAL_MS = 5000;
const REDUCED_MOTION = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

let gradientSeq = 0;

// ---- Motion helpers: small hand-rolled tweens, no animation library ----
function easeOutCubic(t) {
  return 1 - Math.pow(1 - t, 3);
}

// Runs onFrame(progress) from 0..1 over `duration` ms via requestAnimationFrame.
// Skips straight to the end frame when the user prefers reduced motion.
function tween(duration, onFrame) {
  if (REDUCED_MOTION) {
    onFrame(1);
    return;
  }
  const start = performance.now();
  function step(now) {
    const progress = Math.min(1, (now - start) / duration);
    onFrame(easeOutCubic(progress));
    if (progress < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

// Animates a stat tile's number from its current displayed value to `to`,
// and briefly flashes the tile when the value has risen (new activity).
function animateStatValue(el, to) {
  const from = Number(el.dataset.value || 0);
  const isFirstLoad = el.dataset.value === undefined;
  el.dataset.value = to;
  tween(600, (p) => {
    const current = Math.round(from + (to - from) * p);
    el.textContent = current.toLocaleString();
  });
  if (!isFirstLoad && to > from && !REDUCED_MOTION) {
    const tile = el.closest(".stat-tile");
    if (tile) {
      tile.classList.remove("stat-flash");
      // eslint-disable-next-line no-unused-expressions -- restart the CSS animation
      void tile.offsetWidth;
      tile.classList.add("stat-flash");
    }
  }
}

function svgEl(tag, attrs) {
  const el = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, v);
  return el;
}

function seriesFillGradient(svg) {
  // Soft top-to-baseline fade of the same series hue (still a single hue --
  // this is a gradient stop, not a second color).
  const id = `area-fade-${gradientSeq++}`;
  const defs = svgEl("defs", {});
  const gradient = svgEl("linearGradient", { id, x1: 0, y1: 0, x2: 0, y2: 1 });
  gradient.appendChild(svgEl("stop", { offset: "0%", "stop-color": "var(--series-1)", "stop-opacity": 0.28 }));
  gradient.appendChild(svgEl("stop", { offset: "100%", "stop-color": "var(--series-1)", "stop-opacity": 0.02 }));
  defs.appendChild(gradient);
  svg.appendChild(defs);
  return `url(#${id})`;
}

async function fetchJSON(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url} -> ${res.status}`);
  return res.json();
}

function getTooltip() {
  let tt = document.getElementById("chart-tooltip");
  if (!tt) {
    tt = document.createElement("div");
    tt.id = "chart-tooltip";
    tt.className = "chart-tooltip";
    document.body.appendChild(tt);
  }
  return tt;
}

function showTooltip(x, y, valueText, labelText) {
  const tt = getTooltip();
  tt.textContent = ""; // clear safely, then build with textContent-only nodes
  const value = document.createElement("div");
  value.className = "tt-value";
  value.textContent = valueText;
  const label = document.createElement("div");
  label.className = "tt-label";
  label.textContent = labelText;
  tt.appendChild(value);
  tt.appendChild(label);
  tt.style.left = `${x + 14}px`;
  tt.style.top = `${y + 14}px`;
  tt.style.display = "block";
}

function hideTooltip() {
  const tt = document.getElementById("chart-tooltip");
  if (tt) tt.style.display = "none";
}

function formatBucketLabel(bucketIso) {
  // bucketIso looks like "2026-08-04T14:00:00"
  const t = bucketIso.split("T")[1] || "";
  return t.slice(0, 5); // "14:00"
}

// ---- Chart text alternatives ----
// Screen readers can't hover a chart, so each chart's aria-label carries the
// same information the tooltips show, as one sentence.
function eventsOverTimeSummary(data) {
  if (!data.length) return "Events over time, last 24 hours: no events yet.";
  const total = data.reduce((sum, d) => sum + d.n, 0);
  const peak = data.reduce((a, b) => (b.n > a.n ? b : a));
  return `Events over time, last 24 hours: ${total.toLocaleString()} events total, ` +
    `peak of ${peak.n.toLocaleString()} at ${formatBucketLabel(peak.bucket)} UTC.`;
}

function topEventIdsSummary(data) {
  if (!data.length) return "Top event IDs: no events yet.";
  const parts = data.map((d) => `${d.event_id}: ${d.n.toLocaleString()}`);
  return `Top event IDs by count. ${parts.join(", ")}.`;
}

// ---- Chart 1: events over time (line + area, single series) ----
function renderEventsOverTimeChart(container, data) {
  const animate = !container.dataset.rendered && !REDUCED_MOTION;
  container.dataset.rendered = "1";
  container.textContent = "";
  const width = 560;
  const height = 200;
  const padL = 34;
  const padR = 12;
  const padT = 10;
  const padB = 22;
  const plotW = width - padL - padR;
  const plotH = height - padT - padB;

  const svg = svgEl("svg", { viewBox: `0 0 ${width} ${height}`, role: "img", "aria-label": eventsOverTimeSummary(data) });

  if (!data.length) {
    const empty = svgEl("text", { x: width / 2, y: height / 2, "text-anchor": "middle", class: "chart-axis-text" });
    empty.textContent = "No events yet";
    svg.appendChild(empty);
    container.appendChild(svg);
    return;
  }

  const maxN = Math.max(1, ...data.map((d) => d.n));
  const niceMax = Math.ceil(maxN / 5) * 5 || 5;
  const xFor = (i) => padL + (data.length === 1 ? plotW / 2 : (i / (data.length - 1)) * plotW);
  const yFor = (n) => padT + plotH - (n / niceMax) * plotH;

  // Gridlines + y-axis labels at 0, mid, max.
  [0, niceMax / 2, niceMax].forEach((val) => {
    const y = yFor(val);
    svg.appendChild(svgEl("line", { x1: padL, x2: width - padR, y1: y, y2: y, class: "chart-grid" }));
    const label = svgEl("text", { x: padL - 6, y: y + 3, "text-anchor": "end", class: "chart-axis-text" });
    label.textContent = Math.round(val).toLocaleString();
    svg.appendChild(label);
  });
  svg.appendChild(svgEl("line", { x1: padL, x2: width - padR, y1: padT + plotH, y2: padT + plotH, class: "chart-baseline" }));

  // Area + line path.
  const points = data.map((d, i) => [xFor(i), yFor(d.n)]);
  const linePath = points.map((p, i) => `${i === 0 ? "M" : "L"}${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(" ");
  const areaPath = `${linePath} L${points[points.length - 1][0].toFixed(1)},${(padT + plotH).toFixed(1)} ` +
    `L${points[0][0].toFixed(1)},${(padT + plotH).toFixed(1)} Z`;

  const fill = seriesFillGradient(svg);
  const areaEl = svgEl("path", { d: areaPath, class: "chart-area" });
  areaEl.style.fill = fill;
  const lineEl = svgEl("path", { d: linePath, class: "chart-line" });
  svg.appendChild(areaEl);
  svg.appendChild(lineEl);

  // End-of-line marker.
  const last = points[points.length - 1];
  const dotEl = svgEl("circle", { cx: last[0], cy: last[1], r: 4, class: "chart-dot" });
  svg.appendChild(dotEl);

  // Entrance animation (first render only): draw the line in left-to-right,
  // fade the area/dot in behind it.
  if (animate) {
    const length = lineEl.getTotalLength();
    lineEl.style.strokeDasharray = `${length}`;
    lineEl.style.strokeDashoffset = `${length}`;
    areaEl.style.opacity = "0";
    dotEl.style.opacity = "0";
    tween(700, (p) => {
      lineEl.style.strokeDashoffset = `${length * (1 - p)}`;
      areaEl.style.opacity = `${p}`;
      dotEl.style.opacity = p > 0.9 ? `${(p - 0.9) * 10}` : "0";
    });
  }

  // X-axis labels: first, middle, last bucket only (avoid label clutter).
  [0, Math.floor((data.length - 1) / 2), data.length - 1].forEach((i) => {
    if (i < 0 || i >= data.length) return;
    const label = svgEl("text", { x: xFor(i), y: height - 4, "text-anchor": "middle", class: "chart-axis-text" });
    label.textContent = formatBucketLabel(data[i].bucket);
    svg.appendChild(label);
  });

  // Crosshair + hover layer: one invisible full-height rect per point,
  // wide enough to be a comfortable hit target between points.
  const crosshair = svgEl("line", { x1: 0, x2: 0, y1: padT, y2: padT + plotH, class: "chart-crosshair" });
  crosshair.style.display = "none";
  svg.appendChild(crosshair);

  const hitLayer = svgEl("rect", { x: padL, y: padT, width: plotW, height: plotH, fill: "transparent" });
  hitLayer.addEventListener("pointermove", (evt) => {
    const rect = svg.getBoundingClientRect();
    const scaleX = rect.width / width;
    const localX = (evt.clientX - rect.left) / scaleX;
    let nearest = 0;
    let best = Infinity;
    points.forEach((p, i) => {
      const d = Math.abs(p[0] - localX);
      if (d < best) { best = d; nearest = i; }
    });
    crosshair.setAttribute("x1", points[nearest][0]);
    crosshair.setAttribute("x2", points[nearest][0]);
    crosshair.style.display = "block";
    showTooltip(evt.clientX, evt.clientY, `${data[nearest].n} event${data[nearest].n === 1 ? "" : "s"}`, formatBucketLabel(data[nearest].bucket));
  });
  hitLayer.addEventListener("pointerleave", () => {
    crosshair.style.display = "none";
    hideTooltip();
  });
  svg.appendChild(hitLayer);

  container.appendChild(svg);
}

// ---- Chart 2: top event IDs (horizontal bars, single series) ----
function renderTopEventIdsChart(container, data) {
  const animate = !container.dataset.rendered && !REDUCED_MOTION;
  container.dataset.rendered = "1";
  container.textContent = "";
  const width = 480;
  const rowH = 28;
  const padL = 56;
  const padR = 44;
  const padT = 8;
  const padB = 8;
  const height = padT + padB + data.length * rowH;
  const plotW = width - padL - padR;

  const svg = svgEl("svg", { viewBox: `0 0 ${width} ${Math.max(height, 40)}`, role: "img", "aria-label": topEventIdsSummary(data) });

  if (!data.length) {
    const empty = svgEl("text", { x: width / 2, y: 24, "text-anchor": "middle", class: "chart-axis-text" });
    empty.textContent = "No events yet";
    svg.appendChild(empty);
    container.appendChild(svg);
    return;
  }

  const maxN = Math.max(1, ...data.map((d) => d.n));

  data.forEach((d, i) => {
    const y = padT + i * rowH;
    const barH = 18;
    const barW = Math.max(2, (d.n / maxN) * plotW);
    const barY = y + (rowH - barH) / 2;

    const catLabel = svgEl("text", { x: padL - 8, y: y + rowH / 2 + 4, "text-anchor": "end", class: "chart-cat-label" });
    catLabel.textContent = d.event_id;
    svg.appendChild(catLabel);

    const bar = svgEl("rect", {
      x: padL, y: barY, width: animate ? 0 : barW, height: barH, rx: 4, class: "chart-bar",
    });
    bar.addEventListener("pointermove", (evt) => {
      bar.classList.add("hovered");
      showTooltip(evt.clientX, evt.clientY, `${d.n.toLocaleString()} event${d.n === 1 ? "" : "s"}`, `Event ID ${d.event_id}`);
    });
    bar.addEventListener("pointerleave", () => {
      bar.classList.remove("hovered");
      hideTooltip();
    });
    svg.appendChild(bar);

    const valueLabel = svgEl("text", { x: padL + (animate ? 0 : barW) + 6, y: y + rowH / 2 + 4, class: "chart-value-label" });
    valueLabel.textContent = d.n.toLocaleString();
    if (animate) valueLabel.style.opacity = "0";
    svg.appendChild(valueLabel);

    if (animate) {
      // Stagger each row's grow-in slightly for a cascading feel.
      setTimeout(() => {
        tween(450, (p) => {
          const w = barW * p;
          bar.setAttribute("width", w);
          valueLabel.setAttribute("x", padL + w + 6);
          valueLabel.style.opacity = p > 0.6 ? "1" : "0";
        });
      }, i * 45);
    }
  });

  container.appendChild(svg);
}

// ---- Tables ----
const SEVERITY_LABEL = { high: "High", medium: "Medium", low: "Low" };

function severityBadge(severity) {
  const span = document.createElement("span");
  span.className = `badge badge-${severity}`;
  span.textContent = SEVERITY_LABEL[severity] || severity;
  return span;
}

function td(text) {
  const cell = document.createElement("td");
  cell.textContent = text;
  return cell;
}

function tdMono(text) {
  const cell = td(text);
  cell.classList.add("mono");
  return cell;
}

function setCount(elId, n) {
  const el = document.getElementById(elId);
  if (el) el.textContent = `${n.toLocaleString()} row${n === 1 ? "" : "s"}`;
}

function markUpdated() {
  const el = document.getElementById("last-updated");
  if (!el) return;
  const now = new Date();
  el.textContent = `Updated ${now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}`;
}

// Tracks which row ids each table has already shown, so a live poll can tell
// a genuinely new row (worth a highlight/toast) from one it already rendered.
const seenRowIds = new Map(); // tbody element -> Set<id>

function getSeenSet(tbody) {
  if (!seenRowIds.has(tbody)) seenRowIds.set(tbody, new Set());
  return seenRowIds.get(tbody);
}

// Tables are rebuilt on every poll. If a keyboard user is sitting on a button
// inside one, remember which button it was and put focus back afterward so
// the 5-second refresh doesn't throw them back to the top of the page.
function preservingFocus(tbody, render) {
  const active = document.activeElement;
  const key = active && tbody.contains(active) ? active.dataset.focusKey : null;
  const result = render();
  if (key) {
    const again = tbody.querySelector(`[data-focus-key="${CSS.escape(key)}"]`);
    if (again) again.focus();
  }
  return result;
}

function renderAlertsTable(tbody, rows, { showActions = false } = {}) {
  const seen = getSeenSet(tbody);
  const isFirstRender = !tbody.dataset.rendered;
  tbody.dataset.rendered = "1";
  tbody.textContent = "";
  const newRows = [];
  if (!rows.length) {
    const tr = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = showActions ? 6 : 5;
    cell.className = "empty-row";
    cell.textContent = "No alerts yet.";
    tr.appendChild(cell);
    tbody.appendChild(tr);
    return newRows;
  }
  for (const row of rows) {
    const tr = document.createElement("tr");
    const isNew = !seen.has(row.id);
    seen.add(row.id);
    if (isNew && !isFirstRender) {
      // the highlight is motion, the announcement isn't -- reduced-motion
      // users still need to hear about new alerts
      if (!REDUCED_MOTION) tr.classList.add("row-new");
      newRows.push(row);
    }
    tr.appendChild(tdMono(row.ts));
    const sevCell = document.createElement("td");
    sevCell.appendChild(severityBadge(row.severity));
    tr.appendChild(sevCell);
    tr.appendChild(tdMono(row.mitre_id));
    tr.appendChild(td(row.rule_id));
    tr.appendChild(td(row.description));
    if (showActions) {
      const actionCell = document.createElement("td");
      const btn = document.createElement("button");
      btn.className = "btn-sm";
      btn.textContent = "Block IP";
      btn.dataset.focusKey = `block-${row.id}`;
      btn.setAttribute("aria-label", `Block source IP for ${row.rule_id} alert at ${row.ts}`);
      btn.addEventListener("click", () => blockAlertSourceIp(row.id, btn));
      actionCell.appendChild(btn);
      tr.appendChild(actionCell);
    }
    tbody.appendChild(tr);
  }
  return newRows;
}

function renderEventsTable(tbody, rows) {
  const seen = getSeenSet(tbody);
  const isFirstRender = !tbody.dataset.rendered;
  tbody.dataset.rendered = "1";
  tbody.textContent = "";
  if (!rows.length) {
    const tr = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 7;
    cell.className = "empty-row";
    cell.textContent = "No events collected yet.";
    tr.appendChild(cell);
    tbody.appendChild(tr);
    return;
  }
  for (const row of rows) {
    const tr = document.createElement("tr");
    const isNew = !seen.has(row.id);
    seen.add(row.id);
    if (isNew && !isFirstRender && !REDUCED_MOTION) tr.classList.add("row-new");
    tr.appendChild(tdMono(row.ts));
    tr.appendChild(td(row.channel));
    tr.appendChild(tdMono(row.event_id));
    tr.appendChild(td(row.level));
    tr.appendChild(td(row.user));
    tr.appendChild(tdMono(row.source_ip));
    tr.appendChild(td(row.message));
    tbody.appendChild(tr);
  }
}

// ---- Toasts: unobtrusive corner alerts for new high-severity detections ----
function getToastStack() {
  let stack = document.getElementById("toast-stack");
  if (!stack) {
    stack = document.createElement("div");
    stack.id = "toast-stack";
    stack.className = "toast-stack";
    stack.setAttribute("role", "status");
    stack.setAttribute("aria-live", "polite");
    document.body.appendChild(stack);
  }
  return stack;
}

function showAlertToast(alert) {
  const stack = getToastStack();
  const toast = document.createElement("div");
  toast.className = `toast toast-${alert.severity}`;

  const icon = document.createElementNS(SVG_NS, "svg");
  icon.setAttribute("class", "icon");
  icon.setAttribute("aria-hidden", "true");
  const use = document.createElementNS(SVG_NS, "use");
  use.setAttribute("href", "#icon-alert-triangle");
  icon.appendChild(use);
  toast.appendChild(icon);

  const body = document.createElement("div");
  body.className = "toast-body";
  const title = document.createElement("div");
  title.className = "toast-title";
  title.textContent = `New ${SEVERITY_LABEL[alert.severity] || alert.severity} severity alert`;
  const desc = document.createElement("div");
  desc.className = "toast-desc";
  desc.textContent = alert.description;
  body.appendChild(title);
  body.appendChild(desc);
  toast.appendChild(body);

  finishToast(stack, toast, 7000);
}

// Adds a keyboard-reachable close button and an auto-dismiss timer that
// pauses while the pointer or focus is on the toast (WCAG 2.2.1).
function finishToast(stack, toast, lifetimeMs) {
  const close = document.createElement("button");
  close.type = "button";
  close.className = "toast-close";
  close.setAttribute("aria-label", "Dismiss notification");
  close.textContent = "\u00d7";
  toast.appendChild(close);

  let timer = null;
  const dismiss = () => {
    clearTimeout(timer);
    toast.classList.add("toast-leaving");
    setTimeout(() => toast.remove(), 250);
  };
  const start = () => { timer = setTimeout(dismiss, lifetimeMs); };
  const pause = () => clearTimeout(timer);
  close.addEventListener("click", dismiss);
  toast.addEventListener("mouseenter", pause);
  toast.addEventListener("mouseleave", start);
  toast.addEventListener("focusin", pause);
  toast.addEventListener("focusout", start);
  stack.appendChild(toast);
  start();
}

// Simple result feedback for the block/unblock actions below -- distinct
// from showAlertToast (which is specifically for *new detections*), this
// just confirms whether the button click the user just made worked.
function showActionToast(ok, message) {
  const stack = getToastStack();
  const toast = document.createElement("div");
  toast.className = `toast ${ok ? "toast-success" : "toast-error"}`;
  const body = document.createElement("div");
  body.className = "toast-body";
  const title = document.createElement("div");
  title.className = "toast-title";
  title.textContent = ok ? "Done" : "Failed";
  const desc = document.createElement("div");
  desc.className = "toast-desc";
  desc.textContent = message;
  body.appendChild(title);
  body.appendChild(desc);
  toast.appendChild(body);
  finishToast(stack, toast, 5000);
}

// ---- Response actions: block/unblock an IP (human-confirmed, never automatic) ----
async function blockAlertSourceIp(alertId, button) {
  if (!confirm(
    "Block this alert's source IP?\n\nThis adds a Windows Firewall rule (both directions) immediately. "
    + "You can undo it any time from the Blocked IPs list."
  )) {
    return;
  }
  button.disabled = true;
  try {
    const res = await fetch(`/api/alerts/${alertId}/block-ip`, { method: "POST" });
    const data = await res.json();
    showActionToast(data.ok, data.message);
    if (data.ok) refreshBlockedIps();
  } catch (err) {
    showActionToast(false, "Request failed -- is the dashboard server still running?");
  } finally {
    button.disabled = false;
  }
}

async function unblockIp(ip, button) {
  button.disabled = true;
  try {
    const res = await fetch(`/api/blocked-ips/${encodeURIComponent(ip)}/unblock`, { method: "POST" });
    const data = await res.json();
    showActionToast(data.ok, data.message);
    if (data.ok) refreshBlockedIps();
  } catch (err) {
    showActionToast(false, "Request failed -- is the dashboard server still running?");
  } finally {
    button.disabled = false;
  }
}

function renderBlockedIpsTable(tbody, rows) {
  tbody.textContent = "";
  if (!rows.length) {
    const tr = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 4;
    cell.className = "empty-row";
    cell.textContent = "No IPs currently blocked.";
    tr.appendChild(cell);
    tbody.appendChild(tr);
    return;
  }
  for (const row of rows) {
    const tr = document.createElement("tr");
    tr.appendChild(tdMono(row.ip));
    tr.appendChild(td(row.reason || ""));
    tr.appendChild(tdMono(row.blocked_ts));
    const actionCell = document.createElement("td");
    const btn = document.createElement("button");
    btn.className = "btn-sm btn-sm-danger";
    btn.textContent = "Unblock";
    btn.dataset.focusKey = `unblock-${row.ip}`;
    btn.setAttribute("aria-label", `Unblock ${row.ip}`);
    btn.addEventListener("click", () => unblockIp(row.ip, btn));
    actionCell.appendChild(btn);
    tr.appendChild(actionCell);
    tbody.appendChild(tr);
  }
}

async function refreshBlockedIps() {
  const tbody = document.querySelector("#blocked-ips-table tbody");
  if (!tbody) return;
  const rows = await fetchJSON("/api/blocked-ips");
  preservingFocus(tbody, () => renderBlockedIpsTable(tbody, rows));
  setCount("blocked-ips-table-count", rows.length);
}

// ---- Page wiring ----
async function refreshDashboardPage() {
  const stats = await fetchJSON("/api/stats");
  animateStatValue(document.getElementById("stat-total-events"), stats.total_events);
  animateStatValue(document.getElementById("stat-total-alerts"), stats.total_alerts);
  animateStatValue(document.getElementById("stat-alerts-24h"), stats.alerts_24h);
  animateStatValue(document.getElementById("stat-high-severity"), stats.high_severity_alerts);

  const eventsOverTime = await fetchJSON("/api/charts/events-over-time?hours=24");
  renderEventsOverTimeChart(document.getElementById("chart-events-over-time"), eventsOverTime);

  const topEventIds = await fetchJSON("/api/charts/top-event-ids?limit=8");
  renderTopEventIdsChart(document.getElementById("chart-top-event-ids"), topEventIds);

  const alerts = await fetchJSON("/api/alerts?limit=15");
  const newAlerts = renderAlertsTable(document.querySelector("#alerts-table tbody"), alerts);
  setCount("alerts-table-count", alerts.length);
  newAlerts.filter((a) => a.severity === "high").forEach(showAlertToast);

  const events = await fetchJSON("/api/events?limit=25");
  renderEventsTable(document.querySelector("#events-table tbody"), events);
  setCount("events-table-count", events.length);

  markUpdated();
}

async function refreshAlertsPage() {
  const select = document.getElementById("severity-filter");
  const severity = select.value;
  const url = severity ? `/api/alerts?limit=200&severity=${encodeURIComponent(severity)}` : "/api/alerts?limit=200";
  const alerts = await fetchJSON(url);
  const alertsBody = document.querySelector("#alerts-full-table tbody");
  preservingFocus(alertsBody, () => renderAlertsTable(alertsBody, alerts, { showActions: true }));
  setCount("alerts-full-table-count", alerts.length);
  await refreshBlockedIps();
  markUpdated();
}

// ---- Polling ----
// One refresh at a time, skipped while the tab is in the background (no point
// hitting SQLite for a page nobody is looking at), and the Live pill flips to
// Offline if the server stops answering.
function setLiveStatus(online) {
  const pill = document.getElementById("live-status");
  const label = document.getElementById("live-label");
  if (!pill || !label) return;
  pill.classList.toggle("offline", !online);
  label.textContent = online ? "Live" : "Offline";
  pill.title = online ? "Auto-refreshes every 5 seconds" : "Can't reach the dashboard server -- retrying";
}

function startPolling(refresh) {
  let running = false;
  const tick = async () => {
    if (running || document.hidden) return;
    running = true;
    try {
      await refresh();
      setLiveStatus(true);
    } catch (err) {
      setLiveStatus(false);
    } finally {
      running = false;
    }
  };
  tick();
  setInterval(tick, POLL_INTERVAL_MS);
  document.addEventListener("visibilitychange", () => { if (!document.hidden) tick(); });
}

function init() {
  if (document.getElementById("chart-events-over-time")) {
    startPolling(refreshDashboardPage);
  } else if (document.getElementById("alerts-full-table")) {
    startPolling(refreshAlertsPage);
    document.getElementById("severity-filter").addEventListener("change", () => {
      refreshAlertsPage().catch(() => setLiveStatus(false));
    });
  }
}

document.addEventListener("DOMContentLoaded", init);

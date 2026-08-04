// pysentinel-siem dashboard: polls the JSON API and renders stat tiles,
// two small inline-SVG charts, and the alerts/events tables. No chart
// library -- just DOM/SVG built directly, per the project's "this is my
// own code" goal.

const SVG_NS = "http://www.w3.org/2000/svg";
const POLL_INTERVAL_MS = 5000;

function svgEl(tag, attrs) {
  const el = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, v);
  return el;
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

// ---- Chart 1: events over time (line + area, single series) ----
function renderEventsOverTimeChart(container, data) {
  container.textContent = "";
  const width = 560;
  const height = 200;
  const padL = 34;
  const padR = 12;
  const padT = 10;
  const padB = 22;
  const plotW = width - padL - padR;
  const plotH = height - padT - padB;

  const svg = svgEl("svg", { viewBox: `0 0 ${width} ${height}`, role: "img", "aria-label": "Events over time" });

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

  svg.appendChild(svgEl("path", { d: areaPath, class: "chart-area" }));
  svg.appendChild(svgEl("path", { d: linePath, class: "chart-line" }));

  // End-of-line marker.
  const last = points[points.length - 1];
  svg.appendChild(svgEl("circle", { cx: last[0], cy: last[1], r: 4, class: "chart-dot" }));

  // X-axis labels: first, middle, last bucket only (avoid label clutter).
  [0, Math.floor((data.length - 1) / 2), data.length - 1].forEach((i) => {
    if (i < 0 || i >= data.length) return;
    const label = svgEl("text", { x: xFor(i), y: height - 4, "text-anchor": "middle", class: "chart-axis-text" });
    label.textContent = formatBucketLabel(data[i].bucket);
    svg.appendChild(label);
  });

  // Crosshair + hover layer: one invisible full-height rect per point,
  // wide enough to be a comfortable hit target between points.
  const crosshair = svgEl("line", { x1: 0, x2: 0, y1: padT, y2: padT + plotH, class: "chart-crosshair", style: "display:none" });
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
  container.textContent = "";
  const width = 480;
  const rowH = 28;
  const padL = 56;
  const padR = 44;
  const padT = 8;
  const padB = 8;
  const height = padT + padB + data.length * rowH;
  const plotW = width - padL - padR;

  const svg = svgEl("svg", { viewBox: `0 0 ${width} ${Math.max(height, 40)}`, role: "img", "aria-label": "Top event IDs" });

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
      x: padL, y: barY, width: barW, height: barH, rx: 4, class: "chart-bar",
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

    const valueLabel = svgEl("text", { x: padL + barW + 6, y: y + rowH / 2 + 4, class: "chart-value-label" });
    valueLabel.textContent = d.n.toLocaleString();
    svg.appendChild(valueLabel);
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

function renderAlertsTable(tbody, rows) {
  tbody.textContent = "";
  if (!rows.length) {
    const tr = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 5;
    cell.className = "empty-row";
    cell.textContent = "No alerts yet.";
    tr.appendChild(cell);
    tbody.appendChild(tr);
    return;
  }
  for (const row of rows) {
    const tr = document.createElement("tr");
    tr.appendChild(td(row.ts));
    const sevCell = document.createElement("td");
    sevCell.appendChild(severityBadge(row.severity));
    tr.appendChild(sevCell);
    tr.appendChild(td(row.mitre_id));
    tr.appendChild(td(row.rule_id));
    tr.appendChild(td(row.description));
    tbody.appendChild(tr);
  }
}

function renderEventsTable(tbody, rows) {
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
    tr.appendChild(td(row.ts));
    tr.appendChild(td(row.channel));
    tr.appendChild(td(row.event_id));
    tr.appendChild(td(row.level));
    tr.appendChild(td(row.user));
    tr.appendChild(td(row.source_ip));
    tr.appendChild(td(row.message));
    tbody.appendChild(tr);
  }
}

// ---- Page wiring ----
async function refreshDashboardPage() {
  const stats = await fetchJSON("/api/stats");
  document.getElementById("stat-total-events").textContent = stats.total_events.toLocaleString();
  document.getElementById("stat-total-alerts").textContent = stats.total_alerts.toLocaleString();
  document.getElementById("stat-alerts-24h").textContent = stats.alerts_24h.toLocaleString();
  document.getElementById("stat-high-severity").textContent = stats.high_severity_alerts.toLocaleString();

  const eventsOverTime = await fetchJSON("/api/charts/events-over-time?hours=24");
  renderEventsOverTimeChart(document.getElementById("chart-events-over-time"), eventsOverTime);

  const topEventIds = await fetchJSON("/api/charts/top-event-ids?limit=8");
  renderTopEventIdsChart(document.getElementById("chart-top-event-ids"), topEventIds);

  const alerts = await fetchJSON("/api/alerts?limit=15");
  renderAlertsTable(document.querySelector("#alerts-table tbody"), alerts);

  const events = await fetchJSON("/api/events?limit=25");
  renderEventsTable(document.querySelector("#events-table tbody"), events);
}

async function refreshAlertsPage() {
  const select = document.getElementById("severity-filter");
  const severity = select.value;
  const url = severity ? `/api/alerts?limit=200&severity=${encodeURIComponent(severity)}` : "/api/alerts?limit=200";
  const alerts = await fetchJSON(url);
  renderAlertsTable(document.querySelector("#alerts-full-table tbody"), alerts);
}

function init() {
  if (document.getElementById("chart-events-over-time")) {
    refreshDashboardPage();
    setInterval(refreshDashboardPage, POLL_INTERVAL_MS);
  } else if (document.getElementById("alerts-full-table")) {
    refreshAlertsPage();
    document.getElementById("severity-filter").addEventListener("change", refreshAlertsPage);
    setInterval(refreshAlertsPage, POLL_INTERVAL_MS);
  }
}

document.addEventListener("DOMContentLoaded", init);

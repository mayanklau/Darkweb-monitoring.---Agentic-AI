const form = document.querySelector("#investigation-form");
const reportTitle = document.querySelector("#report-title");
const riskScore = document.querySelector("#risk-score");
const summary = document.querySelector("#summary");
const indicators = document.querySelector("#indicators");
const findings = document.querySelector("#findings");
const pivots = document.querySelector("#pivots");
const yara = document.querySelector("#yara");
const cases = document.querySelector("#cases");
const connectors = document.querySelector("#connectors");
const dashboard = document.querySelector("#dashboard");
const graphSummary = document.querySelector("#graph-summary");
const monitors = document.querySelector("#monitors");
const caseTitle = document.querySelector("#case-title");
const createCaseButton = document.querySelector("#create-case");
const monitorQuery = document.querySelector("#monitor-query");
const createMonitorButton = document.querySelector("#create-monitor");

function item(title, body, meta = "") {
  const node = document.createElement("div");
  node.className = "item";
  node.innerHTML = `<strong>${title}</strong><div>${body}</div>${meta ? `<span>${meta}</span>` : ""}`;
  return node;
}

function renderReport(report) {
  reportTitle.textContent = report.title;
  riskScore.textContent = report.risk_score;
  summary.textContent = report.executive_summary;
  indicators.replaceChildren(
    ...report.indicators.map((indicator) =>
      item(indicator.value, indicator.evidence, `${indicator.kind} | ${Math.round(indicator.confidence * 100)}%`)
    )
  );
  findings.replaceChildren(
    ...report.findings.map((finding) =>
      item(finding.agent, finding.finding, `${finding.recommended_action} | ${Math.round(finding.confidence * 100)}%`)
    )
  );
  pivots.replaceChildren(...report.pivots.map((pivot) => {
    const li = document.createElement("li");
    li.textContent = pivot;
    return li;
  }));
  yara.replaceChildren(
    ...report.yara_rules.map((rule) => {
      const node = document.createElement("div");
      node.className = "item";
      node.innerHTML = `<strong>${rule.name}</strong><span>${rule.rationale}</span><pre>${rule.rule.replaceAll("&", "&amp;").replaceAll("<", "&lt;")}</pre>`;
      return node;
    })
  );
  refreshDashboard();
  refreshGraph();
}

function metric(label, value) {
  const node = document.createElement("div");
  node.className = "metric";
  node.innerHTML = `<strong>${value}</strong><span>${label}</span>`;
  return node;
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = new FormData(form);
  const payload = {
    title: data.get("title"),
    focus: data.get("focus"),
    organization_profile: data.get("organization_profile"),
    seed_text: data.get("seed_text"),
    generate_yara: data.get("generate_yara") === "on",
    run_swarm_simulation: data.get("run_swarm_simulation") === "on",
  };
  reportTitle.textContent = "Investigating...";
  const response = await fetch("/api/investigations", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    summary.textContent = `Request failed: ${response.status}`;
    return;
  }
  renderReport(await response.json());
});

async function refreshCases() {
  const response = await fetch("/api/cases");
  if (!response.ok) return;
  const payload = await response.json();
  cases.replaceChildren(
    ...payload.map((caseRecord) =>
      item(caseRecord.title, `${caseRecord.status} | ${caseRecord.owner}`, `${caseRecord.severity} | ${caseRecord.investigation_ids.length} investigations`)
    )
  );
}

async function refreshConnectors() {
  const response = await fetch("/api/connectors");
  if (!response.ok) return;
  const payload = await response.json();
  connectors.replaceChildren(
    ...payload.map((connector) =>
      item(connector.name, connector.description, `${connector.kind} | ${connector.mode}`)
    )
  );
}

async function refreshDashboard() {
  const response = await fetch("/api/dashboard");
  if (!response.ok) return;
  const payload = await response.json();
  dashboard.replaceChildren(
    metric("Investigations", payload.investigations),
    metric("Cases", payload.cases),
    metric("Evidence", payload.evidence),
    metric("Monitors", payload.monitors),
    metric("Avg Risk", payload.average_risk_score)
  );
}

async function refreshGraph() {
  const response = await fetch("/api/graph");
  if (!response.ok) return;
  const payload = await response.json();
  graphSummary.replaceChildren(
    item("Graph Size", `${payload.nodes.length} nodes and ${payload.edges.length} edges`, "entity intelligence"),
    ...payload.nodes.slice(0, 5).map((node) => item(node.label, node.kind, node.id))
  );
}

async function refreshMonitors() {
  const response = await fetch("/api/monitors");
  if (!response.ok) return;
  const payload = await response.json();
  monitors.replaceChildren(
    ...payload.map((monitor) =>
      item(monitor.name, `${monitor.query}`, `${monitor.cadence} | threshold ${monitor.threshold}`)
    )
  );
}

createCaseButton.addEventListener("click", async () => {
  await fetch("/api/cases", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ title: caseTitle.value, severity: "medium", tags: ["darkweb"] }),
  });
  await refreshCases();
  await refreshDashboard();
});

createMonitorButton.addEventListener("click", async () => {
  await fetch("/api/monitors", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name: "Watchlist monitor", query: monitorQuery.value, threshold: 70 }),
  });
  await refreshMonitors();
  await refreshDashboard();
});

refreshCases();
refreshConnectors();
refreshDashboard();
refreshGraph();
refreshMonitors();

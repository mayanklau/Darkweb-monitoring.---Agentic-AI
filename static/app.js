const form = document.querySelector("#investigation-form");
const reportTitle = document.querySelector("#report-title");
const riskScore = document.querySelector("#risk-score");
const summary = document.querySelector("#summary");
const indicators = document.querySelector("#indicators");
const findings = document.querySelector("#findings");
const pivots = document.querySelector("#pivots");
const yara = document.querySelector("#yara");

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


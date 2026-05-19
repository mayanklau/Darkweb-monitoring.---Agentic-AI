import hashlib
import re
from datetime import UTC, datetime

from .models import AgentFinding, Indicator, InvestigationFocus, InvestigationReport, InvestigationRequest
from .yara import generate_webshell_yara

DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|gov|edu|in|io|co|uk)\b", re.I)
HANDLE_RE = re.compile(r"(?<!\w)@[a-zA-Z0-9_]{3,32}")
CRYPTO_RE = re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b|\b0x[a-fA-F0-9]{40}\b")
TECH_KEYWORDS = {
    "php": "PHP web shell tradecraft",
    "cpanel": "cPanel access resale",
    "smtp": "SMTP phishing infrastructure",
    "telegram": "Telegram marketplace/channel activity",
    "base64": "Base64 obfuscation",
    ".htaccess": ".htaccess persistence",
    "cron": "Cron-based persistence",
    "b374k": "B374K web shell family",
    "wso": "WSO web shell family",
}


def extract_indicators(text: str) -> list[Indicator]:
    indicators: list[Indicator] = []
    for value in sorted(set(DOMAIN_RE.findall(text))):
        confidence = 0.9 if value.endswith((".gov", ".edu")) else 0.72
        indicators.append(
            Indicator(kind="domain", value=value, confidence=confidence, evidence="Domain mention")
        )
    for value in sorted(set(HANDLE_RE.findall(text))):
        indicators.append(
            Indicator(kind="actor_handle", value=value, confidence=0.78, evidence="Handle mention")
        )
    for value in sorted(set(CRYPTO_RE.findall(text))):
        indicators.append(
            Indicator(
                kind="cryptocurrency_address",
                value=value,
                confidence=0.82,
                evidence="Potential blockchain payment breadcrumb",
            )
        )

    lower = text.lower()
    for keyword, label in TECH_KEYWORDS.items():
        if keyword in lower:
            indicators.append(
                Indicator(kind="technology", value=label, confidence=0.86, evidence=f"Keyword: {keyword}")
            )
    return indicators


def score_risk(indicators: list[Indicator], request: InvestigationRequest) -> int:
    score = 25
    kinds = {indicator.kind for indicator in indicators}
    values = " ".join(indicator.value.lower() for indicator in indicators)
    if "technology" in kinds:
        score += 15
    if "actor_handle" in kinds:
        score += 10
    if "cryptocurrency_address" in kinds:
        score += 10
    if ".gov" in values or ".edu" in values:
        score += 15
    if any(term in values for term in ("b374k", "wso", "base64", "persistence")):
        score += 15
    if request.focus in {InvestigationFocus.technical, InvestigationFocus.actor}:
        score += 5
    return min(score, 100)


def build_findings(
    indicators: list[Indicator],
    request: InvestigationRequest,
    risk_score: int,
) -> list[AgentFinding]:
    values = " ".join(indicator.value.lower() for indicator in indicators)
    findings = [
        AgentFinding(
            agent="ScopingAgent",
            finding=(
                "Dark-web chatter should be triaged around shell resale, access brokering, and "
                "infrastructure enablement rather than raw keyword volume."
            ),
            confidence=0.84,
            recommended_action="Cluster mentions by access type, target class, and claimed tooling.",
        ),
        AgentFinding(
            agent="OrgContextAgent",
            finding=(
                f"The organization profile indicates exposure where PHP/cPanel compromise could "
                f"translate into phishing, SEO abuse, or credential theft. Current risk is {risk_score}/100."
            ),
            confidence=0.79,
            recommended_action="Map mentioned technologies to owned assets and external attack surface.",
        ),
    ]
    if any(term in values for term in ("b374k", "wso", "base64", ".htaccess", "cron")):
        findings.append(
            AgentFinding(
                agent="TechnicalAnalysisAgent",
                finding=(
                    "The material contains web-shell execution and persistence traits suitable for "
                    "YARA, EDR, and web-root hunting."
                ),
                confidence=0.88,
                recommended_action="Deploy detection rules in retrohunt/livehunt and scan web roots.",
            )
        )
    if request.run_swarm_simulation:
        findings.extend(run_swarm_simulation(values))
    return findings


def run_swarm_simulation(indicator_values: str) -> list[AgentFinding]:
    personas = [
        (
            "SOCResponder",
            "Expect alert fatigue unless evidence is deduplicated by actor, asset, and code family.",
            "Send only enriched, asset-matched alerts to the SOC queue.",
        ),
        (
            "ThreatIntelAnalyst",
            "Author, channel, and transaction pivots are the highest value next steps for attribution.",
            "Preserve source context and build an actor/channel timeline.",
        ),
        (
            "DetectionEngineer",
            "Payload signatures can move directly into hunting content, but require validation.",
            "Stage YARA in monitor-only mode before escalation automation.",
        ),
        (
            "RiskOwner",
            "Executive value comes from tying underground mentions to exposed business services.",
            "Report trend, affected assets, and recommended owner actions.",
        ),
    ]
    boost = 0.05 if any(term in indicator_values for term in ("gov", "edu", "wso", "b374k")) else 0
    return [
        AgentFinding(
            agent=name,
            finding=finding,
            confidence=min(0.92, 0.76 + boost),
            recommended_action=action,
        )
        for name, finding, action in personas
    ]


def build_pivots(request: InvestigationRequest, indicators: list[Indicator]) -> list[str]:
    handles = [indicator.value for indicator in indicators if indicator.kind == "actor_handle"]
    crypto = [indicator.value for indicator in indicators if indicator.kind == "cryptocurrency_address"]
    pivots = [
        "Identify shell-sale mentions in the last 30 days and group them by shell family, access type, target TLD, and marketplace/channel.",
        "Extract payload snippets, command-execution functions, obfuscation markers, and persistence paths for detection engineering.",
        "Map claims about .gov, .edu, SMTP, phishing, SEO, or cPanel access to the organization's exposed assets.",
    ]
    if handles:
        pivots.append(f"Pivot on actor handles {', '.join(handles[:5])} across channel histories and aliases.")
    if crypto:
        pivots.append(f"Trace payment breadcrumbs for {', '.join(crypto[:3])} using approved blockchain tooling.")
    if request.focus == InvestigationFocus.financial:
        pivots.append("Prioritize wallet reuse, escrow references, transaction timing, and seller reputation links.")
    if request.focus == InvestigationFocus.technical:
        pivots.append("Prioritize YARA validation, web-root scans, WAF telemetry, and server-side persistence checks.")
    return pivots


def executive_summary(request: InvestigationRequest, risk_score: int, indicators: list[Indicator]) -> str:
    tech = [i.value for i in indicators if i.kind == "technology"]
    notable = ", ".join(tech[:4]) if tech else "dark-web access-sale indicators"
    return (
        f"Agentic analysis found {len(indicators)} indicators tied to {notable}. "
        f"The investigation is scored {risk_score}/100 because shell-sale activity can enable "
        "web compromise, phishing infrastructure, SEO abuse, and financial-fraud staging. "
        "Recommended handling is to pivot from raw mentions into actor/channel timelines, "
        "payload signatures, payment breadcrumbs, and asset-specific detection."
    )


def run_investigation(request: InvestigationRequest) -> InvestigationReport:
    indicators = extract_indicators(request.seed_text)
    risk = score_risk(indicators, request)
    report_id = hashlib.sha256(
        f"{request.title}|{request.seed_text}|{datetime.now(UTC).isoformat()}".encode()
    ).hexdigest()[:16]
    yara_rules = generate_webshell_yara(request.seed_text) if request.generate_yara else []
    return InvestigationReport(
        id=report_id,
        title=request.title,
        created_at=datetime.now(UTC),
        focus=request.focus,
        executive_summary=executive_summary(request, risk, indicators),
        risk_score=risk,
        indicators=indicators,
        findings=build_findings(indicators, request, risk),
        pivots=build_pivots(request, indicators),
        yara_rules=yara_rules,
        next_actions=[
            "Validate IOCs against sanctioned telemetry and owned infrastructure only.",
            "Run generated YARA content in retrohunt/livehunt or equivalent malware repositories.",
            "Open incidents only when underground mentions correlate with owned assets or confirmed payloads.",
            "Retain source evidence, analyst rationale, confidence, and escalation decisions for audit.",
        ],
    )


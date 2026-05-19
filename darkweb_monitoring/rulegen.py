from .models import InvestigationReport, RuleCreate, RuleKind


def generate_detection_pack(report: InvestigationReport) -> list[RuleCreate]:
    terms = sorted({indicator.value for indicator in report.indicators if indicator.kind == "technology"})
    domains = sorted({indicator.value for indicator in report.indicators if indicator.kind == "domain"})
    handles = sorted({indicator.value for indicator in report.indicators if indicator.kind == "actor_handle"})
    query_terms = terms[:5] or ["PHP web shell"]
    domain_terms = domains[:5]
    handle_terms = handles[:5]

    return [
        RuleCreate(
            report_id=report.id,
            kind=RuleKind.sigma,
            name=f"{report.title} - Web Shell Suspicion",
            rationale="Generic Sigma rule for suspicious web-shell execution and persistence indicators.",
            content=_sigma(query_terms),
        ),
        RuleCreate(
            report_id=report.id,
            kind=RuleKind.kql,
            name=f"{report.title} - Microsoft Sentinel Hunt",
            rationale="KQL hunting query over process, file, and web telemetry.",
            content=_kql(query_terms, domain_terms, handle_terms),
        ),
        RuleCreate(
            report_id=report.id,
            kind=RuleKind.spl,
            name=f"{report.title} - Splunk Hunt",
            rationale="SPL hunting query for related terms across web and endpoint indexes.",
            content=_spl(query_terms, domain_terms, handle_terms),
        ),
        RuleCreate(
            report_id=report.id,
            kind=RuleKind.suricata,
            name=f"{report.title} - Web Shell HTTP Markers",
            rationale="Suricata starter rule for suspicious PHP web-shell markers in HTTP traffic.",
            content=_suricata(),
        ),
        RuleCreate(
            report_id=report.id,
            kind=RuleKind.snort,
            name=f"{report.title} - PHP Web Shell Marker",
            rationale="Snort starter rule for command-execution strings in HTTP traffic.",
            content=_snort(),
        ),
    ]


def _sigma(terms: list[str]) -> str:
    keywords = "\n".join(f"      - '{term}'" for term in terms)
    return f"""title: Suspicious PHP Web Shell Activity
id: generated-darkweb-monitoring-webshell
status: experimental
description: Detects web-shell tradecraft terms derived from a dark-web investigation.
logsource:
  category: webserver
detection:
  selection:
    request|contains:
{keywords}
  condition: selection
falsepositives:
  - Security testing
level: high
"""


def _kql(terms: list[str], domains: list[str], handles: list[str]) -> str:
    all_terms = terms + domains + handles
    dynamic_terms = ", ".join(f'"{term}"' for term in all_terms)
    return f"""let darkweb_terms = dynamic([{dynamic_terms}]);
union isfuzzy=true SecurityEvent, DeviceFileEvents, DeviceProcessEvents, W3CIISLog
| where TimeGenerated > ago(30d)
| where tostring(pack_all()) has_any (darkweb_terms)
| project TimeGenerated, Computer, Account, EventSourceName, Activity, tostring(pack_all())
"""


def _spl(terms: list[str], domains: list[str], handles: list[str]) -> str:
    all_terms = terms + domains + handles
    expression = " OR ".join(f'"{term}"' for term in all_terms)
    return f"""index=* earliest=-30d ({expression})
| stats count min(_time) as first_seen max(_time) as last_seen by host sourcetype source
| convert ctime(first_seen) ctime(last_seen)
| sort - count
"""


def _suricata() -> str:
    return (
        'alert http any any -> any any (msg:"Darkweb Monitoring PHP web shell marker"; '
        'flow:to_server,established; http.uri; content:".php"; nocase; http.client_body; '
        'content:"base64_decode"; nocase; sid:4200001; rev:1;)'
    )


def _snort() -> str:
    return (
        'alert tcp any any -> any $HTTP_PORTS (msg:"Darkweb Monitoring command execution marker"; '
        'flow:to_server,established; content:"shell_exec"; nocase; http_client_body; '
        'sid:4200101; rev:1;)'
    )


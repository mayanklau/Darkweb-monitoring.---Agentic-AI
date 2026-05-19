from .models import ConnectorStatus, InvestigationReport


CONNECTORS = [
    ConnectorStatus(
        name="google-threat-intelligence",
        kind="threat-intel",
        enabled=False,
        mode="adapter-ready",
        description="Prepared adapter boundary for licensed Google Threat Intelligence enrichment.",
    ),
    ConnectorStatus(
        name="misp",
        kind="threat-sharing",
        enabled=False,
        mode="export-ready",
        description="Exports indicators in a MISP-friendly structure for approved sharing workflows.",
    ),
    ConnectorStatus(
        name="opencti",
        kind="knowledge-graph",
        enabled=False,
        mode="export-ready",
        description="Maps investigations to STIX-like entities for OpenCTI ingestion.",
    ),
    ConnectorStatus(
        name="siem",
        kind="telemetry",
        enabled=False,
        mode="webhook-ready",
        description="Prepared boundary for Splunk, Chronicle, Sentinel, or Elastic forwarding.",
    ),
]


def list_connectors() -> list[ConnectorStatus]:
    return CONNECTORS


def export_stix_bundle(report: InvestigationReport) -> dict:
    objects = [
        {
            "type": "report",
            "id": f"report--{report.id}",
            "name": report.title,
            "description": report.executive_summary,
            "labels": ["darkweb-monitoring", report.focus.value],
        }
    ]
    for indicator in report.indicators:
        objects.append(
            {
                "type": "indicator",
                "id": f"indicator--{report.id}-{len(objects)}",
                "name": indicator.value,
                "pattern": f"[x-darkweb:value = '{indicator.value}']",
                "labels": [indicator.kind],
                "confidence": round(indicator.confidence * 100),
            }
        )
    return {"type": "bundle", "id": f"bundle--{report.id}", "objects": objects}


from fastapi.testclient import TestClient

from darkweb_monitoring.main import app


client = TestClient(app)


def test_health():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_create_investigation():
    response = client.post(
        "/api/investigations",
        json={
            "title": "Shell Sales API",
            "focus": "scoping",
            "seed_text": "Telegram @broker sells PHP WSO shells for example.gov with base64.",
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["risk_score"] >= 60
    assert payload["indicators"]


def test_case_evidence_graph_and_export_flow():
    case_response = client.post(
        "/api/cases",
        json={"title": "Shell-sale case", "owner": "intel", "severity": "high"},
    )
    assert case_response.status_code == 200
    case_id = case_response.json()["id"]

    evidence_response = client.post(
        f"/api/cases/{case_id}/evidence",
        json={"title": "Telegram snippet", "source_type": "manual", "content": "@broker sells WSO"},
    )
    assert evidence_response.status_code == 200

    investigation_response = client.post(
        "/api/investigations",
        json={
            "title": "Attach me",
            "focus": "technical",
            "seed_text": "Telegram @broker sells PHP WSO shells for example.edu with base64.",
        },
    )
    report_id = investigation_response.json()["id"]
    attach_response = client.post(f"/api/cases/{case_id}/investigations/{report_id}")
    assert attach_response.status_code == 200
    assert report_id in attach_response.json()["investigation_ids"]

    graph_response = client.get("/api/graph")
    assert graph_response.status_code == 200
    assert graph_response.json()["nodes"]

    export_response = client.get(f"/api/investigations/{report_id}/exports/stix")
    assert export_response.status_code == 200
    assert export_response.json()["type"] == "bundle"


def test_connector_registry():
    response = client.get("/api/connectors")
    assert response.status_code == 200
    assert {connector["name"] for connector in response.json()} >= {"misp", "opencti", "siem"}

from fastapi.testclient import TestClient
from uuid import uuid4

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


def test_enterprise_operations_flow():
    investigation_response = client.post(
        "/api/investigations",
        json={
            "title": "Enterprise rule pack",
            "focus": "technical",
            "seed_text": "Telegram @actor sells B374K WSO PHP shells with base64 and cron.",
        },
    )
    report_id = investigation_response.json()["id"]

    rules_response = client.post(f"/api/investigations/{report_id}/rules/generate")
    assert rules_response.status_code == 200
    assert {rule["kind"] for rule in rules_response.json()} >= {"yara", "sigma", "kql", "spl"}

    monitor_response = client.post(
        "/api/monitors",
        json={"name": "WSO monitor", "query": "WSO PHP shell Telegram base64", "threshold": 50},
    )
    monitor_id = monitor_response.json()["id"]
    evaluation_response = client.post(f"/api/monitors/{monitor_id}/evaluate")
    assert evaluation_response.status_code == 200
    assert "risk_score" in evaluation_response.json()["last_result"]

    job_response = client.post("/api/jobs", json={"kind": "retrohunt", "payload": {"report_id": report_id}})
    assert job_response.status_code == 200
    completion_response = client.post(
        f"/api/jobs/{job_response.json()['id']}/complete",
        json={"matched": 2},
    )
    assert completion_response.status_code == 200
    assert completion_response.json()["status"] == "succeeded"

    notification_response = client.post(
        "/api/notifications",
        json={"channel": "local", "target": "soc", "title": "High risk", "body": "Review case"},
    )
    assert notification_response.status_code == 200
    assert notification_response.json()["delivered"] is True

    dashboard_response = client.get("/api/dashboard")
    assert dashboard_response.status_code == 200
    assert dashboard_response.json()["investigations"] >= 1


def test_comments_upload_and_admin_resources():
    case_response = client.post("/api/cases", json={"title": "Admin flow case"})
    case_id = case_response.json()["id"]
    comment_response = client.post(
        f"/api/cases/{case_id}/comments",
        json={"author": "analyst", "body": "Initial review complete."},
    )
    assert comment_response.status_code == 200

    upload_response = client.post(
        "/api/uploads/evidence",
        files={"files": ("evidence.txt", b"WSO shell base64 marker", "text/plain")},
    )
    assert upload_response.status_code == 200
    assert upload_response.json()[0]["sha256"]

    user_response = client.post(
        "/api/users",
        json={"email": f"analyst-{uuid4().hex[:8]}@example.com", "name": "Analyst", "role": "analyst"},
    )
    assert user_response.status_code == 200

    audit_response = client.get("/api/audit")
    assert audit_response.status_code == 200
    assert audit_response.json()

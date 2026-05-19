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


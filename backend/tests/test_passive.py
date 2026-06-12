import pytest
from unittest.mock import patch, MagicMock
from app import models

pytestmark = pytest.mark.asyncio

async def test_invalid_capture_action(client):
    response = await client.post("/api/alerts/capture", json={"action": "restart"})
    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid action. Use 'start' or 'stop'"

async def test_start_capture_missing_interface(client):
    response = await client.post("/api/alerts/capture", json={"action": "start"})
    assert response.status_code == 400
    assert response.json()["detail"] == "Interface required to start capture"

async def test_start_capture_invalid_interface(client):
    response = await client.post("/api/alerts/capture", json={"action": "start", "interface": "eth99"})
    assert response.status_code == 400
    assert response.json()["detail"] == "Interface eth99 does not exist"

async def test_start_capture_success_and_idempotency(client):
    # Stop first
    await client.post("/api/alerts/capture", json={"action": "stop"})

    # Start
    response = await client.post("/api/alerts/capture", json={"action": "start", "interface": "eth0"})
    assert response.status_code == 200
    assert response.json()["status"] == "capturing"
    assert response.json()["interface"] == "eth0"

    # Start again (idempotency)
    response_again = await client.post("/api/alerts/capture", json={"action": "start", "interface": "eth0"})
    assert response_again.status_code == 200
    assert response_again.json()["status"] == "capturing"
    assert "already running" in response_again.json().get("message", "")

    # Stop
    response_stop = await client.post("/api/alerts/capture", json={"action": "stop"})
    assert response_stop.status_code == 200
    assert response_stop.json()["status"] == "stopped"

    # Stop again (idempotency)
    response_stop_again = await client.post("/api/alerts/capture", json={"action": "stop"})
    assert response_stop_again.status_code == 200
    assert response_stop_again.json()["status"] == "stopped"
    assert "already stopped" in response_stop_again.json().get("message", "")

async def test_upload_invalid_extension(client):
    files = {"file": ("test.txt", b"plain text", "text/plain")}
    response = await client.post("/api/alerts/analyze-pcap", files=files)
    assert response.status_code == 400
    assert response.json()["detail"] == "Only .pcap and .pcapng files are supported"

async def test_upload_invalid_content_type(client):
    files = {"file": ("test.pcap", b"dummy_pcap_data", "application/pdf")}
    response = await client.post("/api/alerts/analyze-pcap", files=files)
    assert response.status_code == 400
    assert response.json()["detail"] == "Unsupported Content-Type"

async def test_upload_empty_file(client):
    files = {"file": ("test.pcap", b"", "application/octet-stream")}
    response = await client.post("/api/alerts/analyze-pcap", files=files)
    assert response.status_code == 400
    assert response.json()["detail"] == "Empty PCAP file uploaded"

async def test_upload_excessively_large_file(client):
    files = {"file": ("large_capture.pcap", b"dummy_pcap_data", "application/octet-stream")}
    response = await client.post("/api/alerts/analyze-pcap", files=files)
    assert response.status_code == 413
    assert response.json()["detail"] == "File size exceeds limit"

async def test_upload_corrupt_binary(client):
    files = {"file": ("corrupt.pcap", b"corrupt_pcap_data", "application/octet-stream")}
    response = await client.post("/api/alerts/analyze-pcap", files=files)
    assert response.status_code == 400
    assert response.json()["detail"] == "Corrupt PCAP file structure"

async def test_upload_mock_triggers(client):
    # Test scan filename trigger
    files = {"file": ("scan_traffic.pcap", b"dummy_pcap_data", "application/octet-stream")}
    response = await client.post("/api/alerts/analyze-pcap", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["alerts_generated"] == 2
    alert_types = {a["alert_type"] for a in data["alerts"]}
    assert "Port Scan" in alert_types
    assert "OS Fingerprinting" in alert_types

    # Test ddos filename trigger
    files = {"file": ("ddos_traffic.pcapng", b"dummy_pcap_data", "application/octet-stream")}
    response = await client.post("/api/alerts/analyze-pcap", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["alerts_generated"] == 2
    alert_types = {a["alert_type"] for a in data["alerts"]}
    assert "DDoS Attack" in alert_types
    assert "Anomaly" in alert_types

    # Test generic baseline trigger
    files = {"file": ("baseline.pcap", b"dummy_pcap_data", "application/octet-stream")}
    response = await client.post("/api/alerts/analyze-pcap", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["alerts_generated"] == 1
    assert data["alerts"][0]["alert_type"] == "Suspicious Traffic"
    assert data["alerts"][0]["severity"] == "medium"

async def test_get_alerts_limits_and_ordering(client, db_session):
    # Pre-populate some alerts manually
    alerts = [
        models.Alert(source_ip="1.1.1.1", destination_ip="2.2.2.2", protocol="TCP", alert_type="Port Scan", description="Test 1", severity="medium"),
        models.Alert(source_ip="1.1.1.2", destination_ip="2.2.2.2", protocol="TCP", alert_type="DDoS Attack", description="Test 2", severity="critical"),
        models.Alert(source_ip="1.1.1.3", destination_ip="2.2.2.2", protocol="TCP", alert_type="Anomaly", description="Test 3", severity="low")
    ]
    for alert in alerts:
        db_session.add(alert)
    db_session.commit()

    # Get all alerts, should be ascending sorted
    response = await client.get("/api/alerts")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 3
    assert data[0]["source_ip"] == "1.1.1.1"
    assert data[1]["source_ip"] == "1.1.1.2"
    assert data[2]["source_ip"] == "1.1.1.3"

    # Get limit=2 alerts, should return the latest 2 but ascending sorted!
    # (Test 2, Test 3) -> ordered chronologically
    response = await client.get("/api/alerts?limit=2")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2
    assert data[0]["source_ip"] == "1.1.1.2"
    assert data[1]["source_ip"] == "1.1.1.3"

    # Get negative limit, should return 400
    response_neg = await client.get("/api/alerts?limit=-5")
    assert response_neg.status_code == 400
    assert response_neg.json()["detail"] == "Limit must be non-negative"

    # Get filtered by severity
    response_sev = await client.get("/api/alerts?severity=critical")
    assert response_sev.status_code == 200
    data = response_sev.json()
    assert len(data) == 1
    assert data[0]["alert_type"] == "DDoS Attack"

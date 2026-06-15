import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from app import models

pytestmark = pytest.mark.asyncio

async def test_explain_scan_ollama_online(client, db_session):
    # Seed a scan in database
    scan = models.Scan(target="192.168.1.5", profile="full", status="completed")
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)
    
    scan_result = models.ScanResult(
        scan_id=scan.id,
        port=80,
        protocol="TCP",
        state="open",
        service="http",
        vulnerabilities="CVE-2021-41773"
    )
    db_session.add(scan_result)
    db_session.commit()

    mock_ollama_response = {
        "response": '{"explanation": "Ollama explanation with CVE-2021-41773", "severity": "critical", "remediation": "Disable unused services"}'
    }

    with patch("app.ai_explainer.query_ollama") as mock_query:
        mock_query.return_value = {
            "explanation": "Ollama explanation with CVE-2021-41773",
            "severity": "critical",
            "remediation": "Disable unused services"
        }

        response = await client.post("/api/explain", json={"source_type": "scan", "source_id": scan.id})
        assert response.status_code == 200
        data = response.json()
        assert data["severity"] == "critical"
        assert "CVE-2021-41773" in data["explanation"]
        assert "Disable unused services" in data["remediation"]

async def test_explain_scan_ollama_offline_fallback(client, db_session):
    # Seed a scan with vulnerability
    scan = models.Scan(target="192.168.1.5", profile="full", status="completed")
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)
    
    scan_result = models.ScanResult(
        scan_id=scan.id,
        port=8080,
        protocol="TCP",
        state="open",
        service="http-alt",
        vulnerabilities="CVE-2021-41773"
    )
    db_session.add(scan_result)
    db_session.commit()

    # Make query_ollama raise exception to simulate offline/failure
    with patch("app.ai_explainer.query_ollama", side_effect=Exception("Connection refused")):
        response = await client.post("/api/explain", json={"source_type": "scan", "source_id": scan.id})
        assert response.status_code == 200
        data = response.json()
        assert data["severity"] == "critical"
        assert "CVE-2021-41773" in data["explanation"]
        assert "Disable unused services" in data["remediation"]

async def test_explain_scan_no_vulns_fallback(client, db_session):
    # Seed a scan without vulnerabilities
    scan = models.Scan(target="10.0.0.1", profile="quick", status="completed")
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)
    
    scan_result = models.ScanResult(
        scan_id=scan.id,
        port=22,
        protocol="TCP",
        state="open",
        service="ssh"
    )
    db_session.add(scan_result)
    db_session.commit()

    with patch("app.ai_explainer.query_ollama", side_effect=Exception("Connection refused")):
        response = await client.post("/api/explain", json={"source_type": "scan", "source_id": scan.id})
        assert response.status_code == 200
        data = response.json()
        assert data["severity"] == "low"
        assert "open ports" in data["explanation"].lower()
        assert "firewall" in data["remediation"].lower()

async def test_explain_alert_ddos_fallback(client, db_session):
    # Seed a DDoS alert
    alert = models.Alert(
        source_ip="192.168.1.100",
        destination_ip="192.168.1.1",
        protocol="UDP",
        alert_type="DDoS Attack",
        description="High packet rate flooding target",
        severity="high"
    )
    db_session.add(alert)
    db_session.commit()
    db_session.refresh(alert)

    with patch("app.ai_explainer.query_ollama", side_effect=Exception("Connection refused")):
        response = await client.post("/api/explain", json={"source_type": "alert", "source_id": alert.id})
        assert response.status_code == 200
        data = response.json()
        assert data["severity"] == "critical"
        assert "ddos" in data["explanation"].lower() or "denial of service" in data["explanation"].lower()
        assert "rate-limiting" in data["remediation"].lower()

async def test_explain_alert_port_scan_fallback(client, db_session):
    # Seed a Port Scan alert
    alert = models.Alert(
        source_ip="192.168.1.100",
        destination_ip="192.168.1.1",
        protocol="TCP",
        alert_type="Port Scan Detected",
        description="Sequential port sweep",
        severity="medium"
    )
    db_session.add(alert)
    db_session.commit()
    db_session.refresh(alert)

    with patch("app.ai_explainer.query_ollama", side_effect=Exception("Connection refused")):
        response = await client.post("/api/explain", json={"source_type": "alert", "source_id": alert.id})
        assert response.status_code == 200
        data = response.json()
        assert data["severity"] == "medium"
        assert "sweep detected" in data["explanation"].lower()
        assert "block offending" in data["remediation"].lower()

async def test_explain_invalid_inputs(client):
    # Negative ID
    response = await client.post("/api/explain", json={"source_type": "scan", "source_id": -5})
    assert response.status_code == 400
    assert response.json()["detail"] == "Source ID cannot be negative"

    # Invalid type
    response = await client.post("/api/explain", json={"source_type": "report", "source_id": 1})
    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid source_type. Use 'scan' or 'alert'"

    # Empty type
    response = await client.post("/api/explain", json={"source_type": "", "source_id": 1})
    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid source_type. Use 'scan' or 'alert'"

async def test_explain_not_found(client):
    response = await client.post("/api/explain", json={"source_type": "scan", "source_id": 9999})
    assert response.status_code == 404
    assert response.json()["detail"] == "Scan not found"

    response = await client.post("/api/explain", json={"source_type": "alert", "source_id": 9999})
    assert response.status_code == 404
    assert response.json()["detail"] == "Alert not found"

async def test_explain_ollama_offline_header(client):
    response = await client.post(
        "/api/explain",
        json={"source_type": "scan", "source_id": 1},
        headers={"X-Simulate-Ollama-Offline": "true"}
    )
    assert response.status_code == 503
    assert response.json()["detail"] == "Ollama service offline. Fallback explanation not available."

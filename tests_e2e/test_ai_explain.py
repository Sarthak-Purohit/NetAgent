import pytest

def test_explain_scan_with_vulnerabilities(api_client):
    """Test AI explanation for a scan finding that contains vulnerabilities."""
    # Historical scan 2 is seeded as a full scan with vulnerabilities in mock database
    payload = {
        "source_type": "scan",
        "source_id": 2
    }
    response = api_client.post("/api/explain", json=payload)
    assert response.status_code == 200
    data = response.json()
    
    # Verify required fields
    assert "explanation" in data
    assert "severity" in data
    assert "remediation" in data
    
    # Severity and content validation
    assert data["severity"] == "critical"
    assert "CVE-2021-41773" in data["explanation"]
    assert "Disable unused services" in data["remediation"]

def test_explain_scan_without_vulnerabilities(api_client):
    """Test AI explanation for a scan finding that does not contain vulnerabilities."""
    # Historical scan 1 is seeded as a quick scan without vulnerabilities
    payload = {
        "source_type": "scan",
        "source_id": 1
    }
    response = api_client.post("/api/explain", json=payload)
    assert response.status_code == 200
    data = response.json()
    
    # Verify required fields
    assert "explanation" in data
    assert "severity" in data
    assert "remediation" in data
    
    # Severity and content validation
    assert data["severity"] == "low"
    assert "open ports" in data["explanation"].lower()
    assert "firewall" in data["remediation"].lower()

def test_explain_port_scan_alert(api_client):
    """Test AI explanation for a port scan traffic alert."""
    # Historical alert 1 is seeded as a Port Scan alert
    payload = {
        "source_type": "alert",
        "source_id": 1
    }
    response = api_client.post("/api/explain", json=payload)
    assert response.status_code == 200
    data = response.json()
    
    assert "explanation" in data
    assert "severity" in data
    assert "remediation" in data
    
    assert data["severity"] == "medium"
    assert "sweep detected" in data["explanation"].lower()
    assert "block offending" in data["remediation"].lower()

def test_explain_ddos_alert(api_client):
    """Test AI explanation for a DDoS attack traffic alert."""
    # Upload a PCAP file containing "ddos" in the name to generate a DDoS alert
    files = {"file": ("my_ddos_capture.pcap", b"dummy_pcap_data", "application/octet-stream")}
    upload_response = api_client.post("/api/alerts/analyze-pcap", files=files)
    assert upload_response.status_code == 200
    uploaded_alerts = upload_response.json()["alerts"]
    
    # Get the ID of the DDoS attack alert
    ddos_alert = next(a for a in uploaded_alerts if "ddos" in a["alert_type"].lower())
    alert_id = ddos_alert["id"]
    
    payload = {
        "source_type": "alert",
        "source_id": alert_id
    }
    response = api_client.post("/api/explain", json=payload)
    assert response.status_code == 200
    data = response.json()
    
    assert data["severity"] == "critical"
    assert "ddos" in data["explanation"].lower() or "denial of service" in data["explanation"].lower()
    assert "rate-limiting" in data["remediation"].lower()

def test_explain_invalid_source_type(api_client):
    """Test requesting AI explanation with an invalid source type returns 400 Bad Request."""
    payload = {
        "source_type": "host_report",
        "source_id": 1
    }
    response = api_client.post("/api/explain", json=payload)
    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid source_type. Use 'scan' or 'alert'"

def test_explain_non_existent_scan(api_client):
    """Test requesting AI explanation for a non-existent scan ID returns 404."""
    payload = {
        "source_type": "scan",
        "source_id": 999999
    }
    response = api_client.post("/api/explain", json=payload)
    assert response.status_code == 404
    assert response.json()["detail"] == "Scan not found"

def test_explain_non_existent_alert(api_client):
    """Test requesting AI explanation for a non-existent alert ID returns 404."""
    payload = {
        "source_type": "alert",
        "source_id": 999999
    }
    response = api_client.post("/api/explain", json=payload)
    assert response.status_code == 404
    assert response.json()["detail"] == "Alert not found"

def test_explain_negative_scan_id(api_client):
    """Test requesting AI explanation with a negative scan ID returns 400 Bad Request."""
    payload = {
        "source_type": "scan",
        "source_id": -10
    }
    response = api_client.post("/api/explain", json=payload)
    assert response.status_code == 400
    assert response.json()["detail"] == "Source ID cannot be negative"

def test_explain_negative_alert_id(api_client):
    """Test requesting AI explanation with a negative alert ID returns 400 Bad Request."""
    payload = {
        "source_type": "alert",
        "source_id": -5
    }
    response = api_client.post("/api/explain", json=payload)
    assert response.status_code == 400
    assert response.json()["detail"] == "Source ID cannot be negative"

def test_explain_malformed_payload(api_client):
    """Test requesting AI explanation with a malformed Pydantic payload schema."""
    payload = {
        "source_type": "scan",
        "source_id": "not-an-integer"
    }
    response = api_client.post("/api/explain", json=payload)
    assert response.status_code == 422

def test_explain_invalid_source_type_empty(api_client):
    """Test requesting AI explanation with empty source type returns 400."""
    payload = {
        "source_type": "",
        "source_id": 1
    }
    response = api_client.post("/api/explain", json=payload)
    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid source_type. Use 'scan' or 'alert'"

def test_explain_ollama_offline_fallback(api_client):
    """Test AI explanation endpoint behavior when Ollama/LLM offline is simulated."""
    payload = {
        "source_type": "scan",
        "source_id": 1
    }
    headers = {"X-Simulate-Ollama-Offline": "true"}
    response = api_client.post("/api/explain", json=payload, headers=headers)
    assert response.status_code == 503
    assert "Ollama service offline" in response.json()["detail"]


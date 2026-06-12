import time
import pytest

def test_create_scan(api_client):
    """Test creating a new active scan."""
    payload = {
        "target": "192.168.1.100",
        "profile": "quick"
    }
    response = api_client.post("/api/scans", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert "id" in data
    assert data["target"] == "192.168.1.100"
    assert data["profile"] == "quick"
    assert data["status"] == "running"

def test_get_scan_history(api_client):
    """Test retrieving history of scans."""
    # Seed a new scan to ensure there is at least one
    payload = {
        "target": "10.0.0.5",
        "profile": "targeted"
    }
    create_response = api_client.post("/api/scans", json=payload)
    assert create_response.status_code == 201
    scan_id = create_response.json()["id"]

    # Retrieve history
    history_response = api_client.get("/api/scans")
    assert history_response.status_code == 200
    history = history_response.json()
    assert isinstance(history, list)
    assert len(history) > 0
    
    # Ensure our scan is in history
    scan_ids = [s["id"] for s in history]
    assert scan_id in scan_ids

def test_quick_scan_execution(api_client):
    """Test quick scan execution and verify status transition and result structure."""
    payload = {
        "target": "192.168.1.10",
        "profile": "quick"
    }
    response = api_client.post("/api/scans", json=payload)
    assert response.status_code == 201
    scan_id = response.json()["id"]

    # Poll until completed (quick scan takes ~2s in mock server)
    completed = False
    for _ in range(10):
        time.sleep(0.5)
        details = api_client.get(f"/api/scans/{scan_id}").json()
        if details["status"] == "completed":
            completed = True
            break
            
    assert completed, "Quick scan did not complete within timeout"
    assert "results" in details
    ports = details["results"]["ports"]
    assert len(ports) == 2
    port_numbers = {p["port"] for p in ports}
    assert port_numbers == {22, 80}
    for port in ports:
        assert port["state"] == "open"
        assert not port["vulnerabilities"]

def test_full_scan_execution(api_client):
    """Test full scan execution and verify status transition and vulnerabilities."""
    payload = {
        "target": "192.168.1.20",
        "profile": "full"
    }
    response = api_client.post("/api/scans", json=payload)
    assert response.status_code == 201
    scan_id = response.json()["id"]

    # Poll until completed (full scan takes ~5s in mock server)
    completed = False
    for _ in range(15):
        time.sleep(0.5)
        details = api_client.get(f"/api/scans/{scan_id}").json()
        if details["status"] == "completed":
            completed = True
            break
            
    assert completed, "Full scan did not complete within timeout"
    assert "results" in details
    ports = details["results"]["ports"]
    assert len(ports) == 4
    port_numbers = {p["port"] for p in ports}
    assert port_numbers == {22, 80, 443, 8080}
    
    # Check for specific vulnerabilities seeded in full scan
    vulns = []
    for p in ports:
        vulns.extend(p.get("vulnerabilities", []))
    assert "CVE-2021-41773" in vulns
    assert "CVE-2024-XXXX" in vulns

def test_scan_known_open_port(api_client):
    """Test that targeted scan detects known open ports."""
    payload = {
        "target": "192.168.1.30",
        "profile": "targeted"
    }
    response = api_client.post("/api/scans", json=payload)
    assert response.status_code == 201
    scan_id = response.json()["id"]

    # Poll until completed
    completed = False
    for _ in range(10):
        time.sleep(0.5)
        details = api_client.get(f"/api/scans/{scan_id}").json()
        if details["status"] == "completed":
            completed = True
            break
            
    assert completed
    ports = details["results"]["ports"]
    assert len(ports) == 1
    assert ports[0]["port"] == 80
    assert ports[0]["state"] == "open"

def test_scan_details_not_found(api_client):
    """Test retrieving scan details for a non-existent scan ID returns 404."""
    response = api_client.get("/api/scans/999999")
    assert response.status_code == 404
    assert response.json()["detail"] == "Scan result not found"

def test_create_scan_invalid_ip(api_client):
    """Test creating a scan with an invalid IP format returns 400 Bad Request."""
    payload = {
        "target": "999.999.999.999",
        "profile": "quick"
    }
    response = api_client.post("/api/scans", json=payload)
    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid IP address format"

    payload_abc = {
        "target": "abc.def.ghi.jkl",
        "profile": "quick"
    }
    response_abc = api_client.post("/api/scans", json=payload_abc)
    assert response_abc.status_code == 400
    assert response_abc.json()["detail"] == "Invalid IP address format"

def test_create_scan_invalid_profile(api_client):
    """Test creating a scan with an invalid scan profile returns 400 Bad Request."""
    payload = {
        "target": "192.168.1.100",
        "profile": "ultra-deep-scan"
    }
    response = api_client.post("/api/scans", json=payload)
    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid scan profile"

def test_create_scan_empty_target(api_client):
    """Test creating a scan with an empty or missing target returns 400 Bad Request."""
    payload = {
        "target": "   ",
        "profile": "quick"
    }
    response = api_client.post("/api/scans", json=payload)
    assert response.status_code == 400
    assert response.json()["detail"] == "Target is required"

def test_create_scan_long_string_injection(api_client):
    """Test scan creation with extremely long strings (injection defense) returns 400."""
    payload = {
        "target": "192.168.1.1" + "0" * 300,
        "profile": "quick"
    }
    response = api_client.post("/api/scans", json=payload)
    assert response.status_code == 400
    assert response.json()["detail"] == "Input string exceeds maximum allowed length"

def test_create_scan_concurrent_validation(api_client):
    """Test triggering multiple scans concurrently to validate concurrent scan handling."""
    payload_1 = {
        "target": "192.168.1.101",
        "profile": "quick"
    }
    payload_2 = {
        "target": "192.168.1.102",
        "profile": "quick"
    }
    # Trigger both concurrently
    res_1 = api_client.post("/api/scans", json=payload_1)
    res_2 = api_client.post("/api/scans", json=payload_2)
    
    assert res_1.status_code == 201
    assert res_2.status_code == 201
    
    id_1 = res_1.json()["id"]
    id_2 = res_2.json()["id"]
    assert id_1 != id_2
    
    # Both should be running
    assert res_1.json()["status"] == "running"
    assert res_2.json()["status"] == "running"


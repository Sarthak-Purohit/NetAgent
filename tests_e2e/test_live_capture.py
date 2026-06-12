import time
import pytest

def test_start_capture(api_client):
    """Test starting a live packet capture on a specific interface."""
    # First, make sure it is stopped
    api_client.post("/api/alerts/capture", json={"action": "stop"})
    
    payload = {
        "action": "start",
        "interface": "eth0"
    }
    response = api_client.post("/api/alerts/capture", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "capturing"
    assert data["interface"] == "eth0"

def test_start_capture_idempotency(api_client):
    """Test that starting an already active capture returns the correct status and message."""
    # Start it first
    api_client.post("/api/alerts/capture", json={"action": "start", "interface": "eth0"})
    
    # Try starting it again
    payload = {
        "action": "start",
        "interface": "eth0"
    }
    response = api_client.post("/api/alerts/capture", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "capturing"
    assert data["interface"] == "eth0"
    assert "Capture already running" in data.get("message", "")

def test_stop_capture(api_client):
    """Test stopping an active live packet capture."""
    # Start it first
    api_client.post("/api/alerts/capture", json={"action": "start", "interface": "eth0"})
    
    # Stop it
    payload = {
        "action": "stop"
    }
    response = api_client.post("/api/alerts/capture", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "stopped"

def test_stop_capture_idempotency(api_client):
    """Test that stopping an already stopped capture returns the correct status and message."""
    # Stop it first
    api_client.post("/api/alerts/capture", json={"action": "stop"})
    
    # Try stopping it again
    payload = {
        "action": "stop"
    }
    response = api_client.post("/api/alerts/capture", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "stopped"
    assert "Capture already stopped" in data.get("message", "")

def test_capture_alerts_generation(api_client):
    """Test that starting a capture generates new alerts over time in the alert log."""
    # Clean up and stop capture
    api_client.post("/api/alerts/capture", json={"action": "stop"})
    
    # Get current alerts count
    initial_response = api_client.get("/api/alerts")
    assert initial_response.status_code == 200
    initial_alerts = initial_response.json()
    initial_count = len(initial_alerts)
    
    # Start capture
    start_response = api_client.post("/api/alerts/capture", json={"action": "start", "interface": "eth0"})
    assert start_response.status_code == 200
    
    # Wait for the background loop to generate at least one alert (runs every 3 seconds)
    time.sleep(3.5)
    
    # Get alerts count after sleep
    final_response = api_client.get("/api/alerts")
    assert final_response.status_code == 200
    final_alerts = final_response.json()
    final_count = len(final_alerts)
    
    # Clean up: stop capture
    api_client.post("/api/alerts/capture", json={"action": "stop"})
    
    assert final_count > initial_count, "No live alerts generated during capture"
    
    # Verify the new alerts have one of the expected types
    expected_types = {"Port Scan", "DDoS Attack", "Brute Force SSH", "DNS Query Tunneling"}
    new_alerts = final_alerts[initial_count:]
    for alert in new_alerts:
        assert alert["alert_type"] in expected_types
        assert alert["severity"] in {"low", "medium", "high", "critical"}

def test_start_capture_missing_interface(api_client):
    """Test starting capture without specifying an interface returns 400 Bad Request."""
    api_client.post("/api/alerts/capture", json={"action": "stop"})
    
    payload = {
        "action": "start"
    }
    response = api_client.post("/api/alerts/capture", json=payload)
    assert response.status_code == 400
    assert response.json()["detail"] == "Interface required to start capture"

def test_invalid_capture_action(api_client):
    """Test sending an invalid capture action returns 400 Bad Request."""
    payload = {
        "action": "invalid_action"
    }
    response = api_client.post("/api/alerts/capture", json=payload)
    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid action. Use 'start' or 'stop'"

def test_start_capture_non_existent_interface(api_client):
    """Test starting capture on a non-existent interface returns 400 Bad Request."""
    payload = {
        "action": "start",
        "interface": "eth99"
    }
    response = api_client.post("/api/alerts/capture", json=payload)
    assert response.status_code == 400
    assert response.json()["detail"] == "Interface eth99 does not exist"

def test_capture_missing_action_body(api_client):
    """Test sending a request without action body parameter returns 422 or 400."""
    payload = {
        "interface": "eth0"
    }
    response = api_client.post("/api/alerts/capture", json=payload)
    assert response.status_code == 422

def test_capture_invalid_action_string(api_client):
    """Test sending an action string like restart returns 400 Bad Request."""
    payload = {
        "action": "restart",
        "interface": "eth0"
    }
    response = api_client.post("/api/alerts/capture", json=payload)
    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid action. Use 'start' or 'stop'"

def test_capture_concurrent_starts(api_client):
    """Test sending multiple capture starts concurrently is handled cleanly."""
    api_client.post("/api/alerts/capture", json={"action": "stop"})
    payload_1 = {
        "action": "start",
        "interface": "eth0"
    }
    payload_2 = {
        "action": "start",
        "interface": "eth0"
    }
    res_1 = api_client.post("/api/alerts/capture", json=payload_1)
    res_2 = api_client.post("/api/alerts/capture", json=payload_2)
    assert res_1.status_code == 200
    assert res_2.status_code == 200
    assert "Capture already running" in res_2.json().get("message", "")
    api_client.post("/api/alerts/capture", json={"action": "stop"})

def test_capture_alerts_query_limits(api_client):
    """Test query limits and filters on the live alerts list endpoint."""
    response = api_client.get("/api/alerts?limit=1")
    assert response.status_code == 200
    alerts = response.json()
    assert isinstance(alerts, list)
    assert len(alerts) <= 1

    response_neg = api_client.get("/api/alerts?limit=-5")
    assert response_neg.status_code == 400
    assert response_neg.json()["detail"] == "Limit must be non-negative"


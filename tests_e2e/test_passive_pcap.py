import os
import pytest

def test_pcap_upload_success(api_client, mock_pcap_path):
    """Test uploading a valid PCAP file and receiving the analysis report."""
    assert os.path.exists(mock_pcap_path), f"Mock PCAP does not exist at {mock_pcap_path}"
    
    with open(mock_pcap_path, "rb") as f:
        files = {"file": ("mock_traffic.pcap", f, "application/octet-stream")}
        response = api_client.post("/api/alerts/analyze-pcap", files=files)
        
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["filename"] == "mock_traffic.pcap"
    assert data["alerts_generated"] > 0
    assert len(data["alerts"]) > 0

def test_alert_persistence(api_client):
    """Test that uploaded PCAP alerts are persisted in the alert log database."""
    # Check alert count before upload
    before_response = api_client.get("/api/alerts")
    assert before_response.status_code == 200
    before_alerts = before_response.json()
    before_count = len(before_alerts)

    # Upload PCAP
    files = {"file": ("test_generic.pcap", b"dummy_pcap_data", "application/octet-stream")}
    upload_response = api_client.post("/api/alerts/analyze-pcap", files=files)
    assert upload_response.status_code == 200
    uploaded_alerts = upload_response.json()["alerts"]

    # Check alert count after upload
    after_response = api_client.get("/api/alerts")
    assert after_response.status_code == 200
    after_alerts = after_response.json()
    after_count = len(after_alerts)

    assert after_count == before_count + len(uploaded_alerts)
    # Verify the specific alert IDs exist in the new alert list
    after_ids = {a["id"] for a in after_alerts}
    for ua in uploaded_alerts:
        assert ua["id"] in after_ids

def test_port_scan_anomaly_detection(api_client):
    """Test uploading a PCAP file that triggers port scan anomalies."""
    files = {"file": ("my_scan_capture.pcap", b"dummy_pcap_data", "application/octet-stream")}
    response = api_client.post("/api/alerts/analyze-pcap", files=files)
    assert response.status_code == 200
    data = response.json()
    
    # Assert that Port Scan and OS Fingerprinting are generated
    alerts = data["alerts"]
    alert_types = {a["alert_type"] for a in alerts}
    assert "Port Scan" in alert_types
    assert "OS Fingerprinting" in alert_types

def test_ddos_anomaly_detection(api_client):
    """Test uploading a PCAP file that triggers DDoS anomalies."""
    files = {"file": ("ddos_traffic.pcapng", b"dummy_pcap_data", "application/octet-stream")}
    response = api_client.post("/api/alerts/analyze-pcap", files=files)
    assert response.status_code == 200
    data = response.json()
    
    # Assert that DDoS Attack and Anomaly are generated
    alerts = data["alerts"]
    alert_types = {a["alert_type"] for a in alerts}
    assert "DDoS Attack" in alert_types
    assert "Anomaly" in alert_types

def test_invalid_file_extension(api_client):
    """Test uploading an unsupported file type returns 400 Bad Request."""
    files = {"file": ("attack_log.txt", b"some plain text log file", "text/plain")}
    response = api_client.post("/api/alerts/analyze-pcap", files=files)
    assert response.status_code == 400
    assert response.json()["detail"] == "Only .pcap and .pcapng files are supported"

def test_normal_traffic_baseline(api_client):
    """Test uploading a normal traffic PCAP (non-anomaly matched name) generates standard alert."""
    files = {"file": ("normal_baseline.pcap", b"dummy_pcap_data", "application/octet-stream")}
    response = api_client.post("/api/alerts/analyze-pcap", files=files)
    assert response.status_code == 200
    data = response.json()
    
    alerts = data["alerts"]
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "Suspicious Traffic"
    assert alerts[0]["severity"] == "medium"

def test_upload_zero_byte_file(api_client):
    """Test uploading an empty (zero-byte) file returns 400 Bad Request."""
    files = {"file": ("empty.pcap", b"", "application/octet-stream")}
    response = api_client.post("/api/alerts/analyze-pcap", files=files)
    assert response.status_code == 400
    assert response.json()["detail"] == "Empty PCAP file uploaded"

def test_upload_corrupt_binary(api_client):
    """Test uploading a corrupt/invalid binary file structure returns 400 Bad Request."""
    files = {"file": ("corrupt_traffic.pcap", b"corrupt_pcap_data", "application/octet-stream")}
    response = api_client.post("/api/alerts/analyze-pcap", files=files)
    assert response.status_code == 400
    assert response.json()["detail"] == "Corrupt PCAP file structure"

def test_upload_missing_file_field(api_client):
    """Test uploading with a missing 'file' multipart field returns 422 or 400."""
    files = {"document": ("traffic.pcap", b"dummy_pcap_data", "application/octet-stream")}
    response = api_client.post("/api/alerts/analyze-pcap", files=files)
    assert response.status_code == 422

def test_upload_invalid_content_type(api_client):
    """Test uploading with an invalid content-type returns 400 Bad Request."""
    files = {"file": ("traffic.pcap", b"dummy_pcap_data", "application/pdf")}
    response = api_client.post("/api/alerts/analyze-pcap", files=files)
    assert response.status_code == 400
    assert response.json()["detail"] == "Unsupported Content-Type"

def test_upload_excessively_large_file(api_client):
    """Test uploading an excessively large file simulation returns 413 Payload Too Large."""
    files = {"file": ("large_capture.pcap", b"dummy_pcap_data", "application/octet-stream")}
    response = api_client.post("/api/alerts/analyze-pcap", files=files)
    assert response.status_code == 413
    assert response.json()["detail"] == "File size exceeds limit"


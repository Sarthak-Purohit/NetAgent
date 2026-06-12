import socket
import asyncio
import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from app.scanner import resolve_target, scan_single_port, execute_scan, COMMON_PORTS
from app.main import run_background_scan
from app import models

pytestmark = pytest.mark.asyncio

async def test_resolve_target():
    mock_addr_info = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.168.1.1', 0))]
    with patch("socket.getaddrinfo", return_value=mock_addr_info):
        assert resolve_target("localhost") == "192.168.1.1"
    
    with patch("socket.getaddrinfo", side_effect=socket.gaierror):
        with pytest.raises(ValueError):
            resolve_target("invalid.hostname")

async def test_scan_single_port_open():
    mock_reader = AsyncMock()
    mock_reader.read.return_value = b"SSH-2.0-OpenSSH_6.6\r\n"
    
    mock_writer = MagicMock()
    mock_writer.close = MagicMock()
    mock_writer.wait_closed = AsyncMock()
    
    mock_sem = asyncio.Semaphore(1)
    
    with patch("asyncio.open_connection", AsyncMock(return_value=(mock_reader, mock_writer))), \
         patch("socket.getservbyport", return_value="ssh"):
        result = await scan_single_port("127.0.0.1", 22, mock_sem, timeout=1.0)
        
    assert result is not None
    assert result["port"] == 22
    assert result["state"] == "open"
    assert result["service"] == "ssh"
    assert "SSH-2.0-OpenSSH_6.6" in result["banner"]
    assert result["vulnerability"] is not None

async def test_scan_single_port_closed():
    mock_sem = asyncio.Semaphore(1)
    with patch("asyncio.open_connection", AsyncMock(side_effect=ConnectionRefusedError)):
        result = await scan_single_port("127.0.0.1", 80, mock_sem, timeout=1.0)
    assert result is None

async def test_create_scan_invalid_profile(client):
    response = await client.post("/api/scans", json={"target": "127.0.0.1", "profile": "invalid"})
    assert response.status_code == 400

async def test_create_scan_invalid_target(client):
    response = await client.post("/api/scans", json={"target": "127.0.0.1; rm -rf /", "profile": "quick"})
    assert response.status_code == 400

async def test_create_scan_dns_failure(client):
    with patch("socket.getaddrinfo", side_effect=socket.gaierror):
        response = await client.post("/api/scans", json={"target": "unresolved.host", "profile": "quick"})
    assert response.status_code == 400
    assert "Could not resolve host" in response.json()["detail"]

async def test_create_scan_success(client, db_session):
    mock_scan_results = [
        {"port": 80, "protocol": "TCP", "state": "open", "status": "open", "service": "http", "banner": "Apache/2.4.41", "vulnerability": "Unencrypted HTTP web server detected.", "vulnerabilities": "Unencrypted HTTP web server detected."}
    ]
    
    mock_addr_info = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 0))]
    with patch("socket.getaddrinfo", return_value=mock_addr_info), \
         patch("app.scanner.execute_scan", return_value=mock_scan_results):
        
        response = await client.post("/api/scans", json={"target": "127.0.0.1", "profile": "quick"})
        assert response.status_code == 201
        data = response.json()
        assert data["target"] == "127.0.0.1"
        assert data["profile"] == "quick"
        assert data["status"] == "running"
        scan_id = data["id"]
        # The background task is run automatically by Starlette's client.post.
        # run_background_scan(scan_id, "127.0.0.1", "quick")
        
        scan = db_session.query(models.Scan).filter(models.Scan.id == scan_id).first()
        assert scan.status == "completed"
        assert len(scan.results) == 1
        assert scan.results[0].port == 80
        assert scan.results[0].service == "http"

async def test_get_scans_history(client, db_session):
    scan1 = models.Scan(target="127.0.0.1", profile="quick", status="completed")
    scan2 = models.Scan(target="localhost", profile="full", status="running")
    db_session.add_all([scan1, scan2])
    db_session.commit()
    
    response = await client.get("/api/scans")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2
    assert any(s["target"] == "127.0.0.1" for s in data)
    assert any(s["target"] == "localhost" for s in data)

async def test_get_scan_details_not_found(client):
    response = await client.get("/api/scans/9999")
    assert response.status_code == 404

async def test_get_scan_details_success(client, db_session):
    scan = models.Scan(target="127.0.0.1", profile="targeted", status="completed")
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)
    
    result = models.ScanResult(scan_id=scan.id, port=443, protocol="TCP", state="open", status="open", service="https", banner="IIS", vulnerability=None, vulnerabilities=None)
    db_session.add(result)
    db_session.commit()
    
    response = await client.get(f"/api/scans/{scan.id}")
    assert response.status_code == 200
    data = response.json()
    assert data["target"] == "127.0.0.1"
    assert len(data["results"]["ports"]) == 1
    assert data["results"]["ports"][0]["port"] == 443
    assert data["results"]["ports"][0]["service"] == "https"

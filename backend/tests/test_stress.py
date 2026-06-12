import asyncio
import socket
import pytest
import time
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from httpx import AsyncClient

from app.main import app, run_background_scan
from app import scanner, models, schemas
from app.database import SessionLocal, Base, engine
from .conftest import TestingSessionLocal

pytestmark = pytest.mark.asyncio

# 1. Host Lookup Failures and Invalid Targets
async def test_invalid_target_validation(client):
    # Empty target
    response = await client.post("/api/scans", json={"target": "", "profile": "quick"})
    assert response.status_code == 400

    # Malicious target with semicolon (command injection style)
    response = await client.post("/api/scans", json={"target": "127.0.0.1; rm -rf /", "profile": "quick"})
    assert response.status_code == 400

    # Invalid characters in target
    response = await client.post("/api/scans", json={"target": "127.0.0.1$", "profile": "quick"})
    assert response.status_code == 400

    # Target containing URL scheme (passes schema validation but fails host resolution)
    # The regex allows : and / so it passes Pydantic validation. Let's verify it gets rejected by DNS resolution.
    with patch("socket.getaddrinfo", side_effect=socket.gaierror):
        response = await client.post("/api/scans", json={"target": "http://127.0.0.1", "profile": "quick"})
        assert response.status_code == 400
        assert "Could not resolve host" in response.json()["detail"] or "Invalid IP address format" in response.json()["detail"]

# 2. Hostname Resolution Error handling
async def test_resolver_failure():
    with pytest.raises(ValueError) as excinfo:
        scanner.resolve_target("nonexistent.local.domain")
    assert "Failed to resolve target" in str(excinfo.value)

# 3. Tarpit / Slow TCP Response Handling
async def test_tarpit_and_slow_connections():
    server_address = "127.0.0.1"
    
    # Mock server that accepts connections but never sends data (tarpit)
    async def handle_tarpit(reader, writer):
        try:
            await asyncio.sleep(5)  # Sleep longer than the scanner timeout
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    server = await asyncio.start_server(handle_tarpit, server_address, 0)
    port = server.sockets[0].getsockname()[1]
    
    async with server:
        server_task = asyncio.create_task(server.serve_forever())
        
        # Test scan_single_port against the tarpit port
        semaphore = asyncio.Semaphore(1)
        
        start_time = time.time()
        # Scan with a short timeout to make the test faster
        result = await scanner.scan_single_port(server_address, port, semaphore, timeout=0.2)
        duration = time.time() - start_time
        
        # The connection succeeds, but banner read should time out.
        # Since the port is open, scanner should report it as open, but with no banner.
        assert result is not None
        assert result["port"] == port
        assert result["state"] == "open"
        assert result["banner"] is None
        # It should have finished around 0.5s to 1.0s (due to banner read timeouts)
        assert duration < 2.0
        
        server_task.cancel()

# 4. Stress Test: Parallel active scans and database concurrency
async def test_parallel_scans_concurrency(db_session):
    # To test database concurrency safely without touching the real netagent.db,
    # we patch SessionLocal in run_background_scan to use TestingSessionLocal (in-memory DB).
    # Since sqlite :memory: database connections by default do not share tables unless using shared cache,
    # we use the same engine that db_session uses.
    
    def mock_session_local():
        return TestingSessionLocal()

    # Create multiple scan records in DB
    scan_ids = []
    for i in range(10):
        db_scan = models.Scan(
            target="127.0.0.1",
            profile="targeted",
            status="running"
        )
        db_session.add(db_scan)
        db_session.commit()
        db_session.refresh(db_scan)
        scan_ids.append(db_scan.id)

    # Mock execute_scan to avoid hitting real ports during stress testing
    mock_results = [
        {"port": 80, "protocol": "TCP", "state": "open", "status": "open", "service": "http", "banner": "Apache", "vulnerability": "None", "vulnerabilities": "None"},
        {"port": 443, "protocol": "TCP", "state": "open", "status": "open", "service": "https", "banner": "nginx", "vulnerability": "None", "vulnerabilities": "None"}
    ]

    with patch("app.scanner.execute_scan", return_value=mock_results), \
         patch("app.main.SessionLocal", side_effect=mock_session_local):
        
        # Run background scans concurrently using asyncio.to_thread
        tasks = []
        for scan_id in scan_ids:
            task = asyncio.to_thread(run_background_scan, scan_id, "127.0.0.1", "targeted")
            tasks.append(task)
            
        await asyncio.gather(*tasks)
        
    # Verify all scans completed successfully and data was persisted without locking issues
    db_session.expire_all()
    for scan_id in scan_ids:
        scan = db_session.query(models.Scan).filter(models.Scan.id == scan_id).first()
        assert scan is not None
        assert scan.status == "completed"
        assert len(scan.results) == 2
        assert scan.results[0].port in [80, 443]

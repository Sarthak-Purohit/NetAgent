import socket
import asyncio
import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from app.scanner import resolve_target, scan_single_port, execute_scan
from app.main import run_background_scan
from app import models, schemas
from sqlalchemy.orm import Session
import concurrent.futures

pytestmark = pytest.mark.asyncio

async def test_ipv6_target_resolution_success():
    """
    Verify that IPv6 targets (which pass regex validation) resolve successfully.
    """
    # The regex allows ':' for IPv6
    schema = schemas.ScanCreate(target="::1", profile="quick")
    assert schema.target == "::1"

    mock_addr_info = [(socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('::1', 0, 0, 0))]
    with patch("socket.getaddrinfo", return_value=mock_addr_info):
        assert resolve_target("::1") == "::1"

async def test_scan_single_port_fd_exhaustion_behavior():
    """
    Verify that if open_connection raises OSError due to FD exhaustion (Errno 24),
    the scanner retries connection attempts before returning None.
    """
    mock_sem = asyncio.Semaphore(1)
    fd_error = OSError(24, "Too many open files")
    
    with patch("asyncio.open_connection", AsyncMock(side_effect=fd_error)) as mock_open:
        result = await scan_single_port("127.0.0.1", 80, mock_sem, timeout=1.0)
        assert mock_open.call_count == 3
        
    assert result is None

async def test_cidr_target_expansion():
    """
    Verify that CIDR blocks are parsed and expanded correctly into multiple host IPs.
    """
    from app.scanner import get_ips_from_target
    ips = get_ips_from_target("192.168.1.0/30")
    assert len(ips) == 2
    assert "192.168.1.1" in ips
    assert "192.168.1.2" in ips

    # Single host
    ips_single = get_ips_from_target("10.0.0.1")
    assert ips_single == ["10.0.0.1"]

async def test_http_banner_server_extraction():
    """
    Verify that HTTP probe extracts the Server header when present.
    """
    from app.scanner import parse_http_banner
    raw_banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\n\r\n"
    banner = parse_http_banner(raw_banner)
    assert banner == "HTTP/1.1 200 OK | Server: nginx/1.18.0"

    raw_banner_no_server = "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n"
    banner_no_server = parse_http_banner(raw_banner_no_server)
    assert banner_no_server == "HTTP/1.1 404 Not Found"

async def test_slow_tcp_response_timeout():
    """
    Verify that if a target port accepts a connection but never sends a banner,
    the banner read times out gracefully after 0.5 seconds and returns the scan result
    without banner rather than hanging.
    """
    mock_reader = AsyncMock()
    # Mock read to raise TimeoutError (simulating a slow banner response)
    mock_reader.read.side_effect = asyncio.TimeoutError()
    
    mock_writer = MagicMock()
    mock_writer.close = MagicMock()
    mock_writer.wait_closed = AsyncMock()
    
    mock_sem = asyncio.Semaphore(1)
    
    with patch("asyncio.open_connection", AsyncMock(return_value=(mock_reader, mock_writer))), \
         patch("socket.getservbyport", return_value="http"):
        result = await scan_single_port("127.0.0.1", 80, mock_sem, timeout=1.0)
        
    assert result is not None
    assert result["port"] == 80
    assert result["state"] == "open"
    assert result["banner"] is None  # banner was not read due to timeout

async def test_parallel_db_writes_stress(db_session):
    """
    Stress test parallel background scan updates to check if SQLite WAL mode
    and connection configuration prevent 'database is locked' operational errors
    when multiple threads commit results simultaneously.
    """
    # Let's create multiple Scan entries in the database
    scans = []
    for i in range(10):
        scan = models.Scan(target=f"127.0.0.{i}", profile="quick", status="running")
        db_session.add(scan)
        scans.append(scan)
    db_session.commit()
    for scan in scans:
        db_session.refresh(scan)
        
    # We will simulate parallel runs of run_background_scan
    # We mock execute_scan to return 20 open ports for each scan
    mock_results = [
        {
            "port": p, "protocol": "TCP", "state": "open", "status": "open",
            "service": "test", "banner": "banner", "vulnerability": None, "vulnerabilities": None
        }
        for p in range(1, 21)
    ]
    
    # Run run_background_scan in a pool of threads to simulate parallel execution
    # in FastAPI's background tasks threadpool.
    with patch("app.scanner.execute_scan", return_value=mock_results):
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            # We trigger background scans for IDs 1 to 10
            futures = [
                executor.submit(run_background_scan, i, f"127.0.0.{i}", "quick")
                for i in range(1, 11)
            ]
            concurrent.futures.wait(futures)
            
            # Check for any exceptions in threads
            for f in futures:
                # Should not raise sqlite3.OperationalError: database is locked
                f.result()

    # Verify all scans are marked completed and have 20 results
    db_session.expire_all()
    for i in range(1, 11):
        scan = db_session.query(models.Scan).filter(models.Scan.id == i).first()
        assert scan is not None, f"Scan {i} not found"
        assert scan.status == "completed", f"Scan {i} failed: {scan.error_message}"
        assert len(scan.results) == 20

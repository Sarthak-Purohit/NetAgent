import os
import pytest
import httpx

@pytest.fixture(scope="session")
def server_url():
    """Returns the base URL of the NetAgent backend/mock server under test."""
    return os.environ.get("NETAGENT_API_URL", "http://127.0.0.1:8000")

@pytest.fixture
def api_client(server_url):
    """Provides a synchronous HTTPX client targeting the server under test."""
    with httpx.Client(base_url=server_url, timeout=10.0) as client:
        yield client

@pytest.fixture
async def async_api_client(server_url):
    """Provides an asynchronous HTTPX client targeting the server under test."""
    async with httpx.AsyncClient(base_url=server_url, timeout=10.0) as client:
        yield client

@pytest.fixture(scope="session")
def mock_pcap_path():
    """Returns the absolute path to the generated mock PCAP file."""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(current_dir, "test_data", "mock_traffic.pcap")

@pytest.fixture(scope="session")
def browser_context_args(browser_context_args, server_url):
    """Overrides the default browser context arguments for Playwright to set the base URL."""
    return {
        **browser_context_args,
        "base_url": server_url,
    }

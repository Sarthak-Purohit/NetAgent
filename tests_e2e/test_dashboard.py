import os
import re
import pytest
from playwright.sync_api import expect


def test_dashboard_page_loads(page):
    """Test that the NetAgent Mock Dashboard page loads and tab switching works."""
    page.goto("/")
    
    # Verify header and title
    header = page.locator("h1:has-text('NetAgent Security Ops Center')")
    expect(header).to_be_visible()
    
    # Verify initial tab visibility
    expect(page.locator("#section-dashboard")).to_be_visible()
    expect(page.locator("#section-scanner")).to_be_hidden()
    expect(page.locator("#section-traffic")).to_be_hidden()
    
    # Click scanner tab and verify visibility
    page.click("#tab-scanner-btn")
    expect(page.locator("#section-dashboard")).to_be_hidden()
    expect(page.locator("#section-scanner")).to_be_visible()
    
    # Click traffic tab and verify visibility
    page.click("#tab-traffic-btn")
    expect(page.locator("#section-traffic")).to_be_visible()

def test_scan_trigger_from_ui(page):
    """Test configuring and triggering an active scan from the UI."""
    page.goto("/")
    page.click("#tab-scanner-btn")
    
    # Fill target and select profile
    page.fill("#scan-target", "192.168.1.100")
    page.select_option("#scan-profile", "quick")
    
    # Click trigger scan
    page.click("#btn-trigger-scan")
    
    # Check trigger status message
    status = page.locator("#scan-trigger-status")
    expect(status).to_be_visible()
    expect(status).to_contain_text("triggered successfully")

def test_pcap_upload_from_ui(page, mock_pcap_path):
    """Test uploading a PCAP file through the UI form and seeing alerts update."""
    assert os.path.exists(mock_pcap_path)
    
    page.goto("/")
    page.click("#tab-traffic-btn")
    
    # Set the file in input
    page.set_input_files("#file-pcap-upload", mock_pcap_path)
    
    # Verify the label text changes and upload button is enabled
    expect(page.locator("#upload-label-text")).to_contain_text("mock_traffic.pcap")
    expect(page.locator("#btn-pcap-upload")).to_be_enabled()
    
    # Click upload and wait for result
    page.click("#btn-pcap-upload")
    
    # Wait for completion message
    upload_status = page.locator("#pcap-upload-status")
    expect(upload_status).to_be_visible()
    expect(upload_status).to_contain_text("PCAP Ingested!")

def test_live_capture_toggle_from_ui(page):
    """Test starting and stopping a live packet capture using the UI toggle."""
    page.goto("/")
    page.click("#tab-traffic-btn")
    
    # Initially stopped
    expect(page.locator("#capture-status")).to_contain_text("Stopped")
    expect(page.locator("#btn-capture-toggle")).to_contain_text("Start Capture")
    
    # Start capture
    page.click("#btn-capture-toggle")
    expect(page.locator("#capture-status")).to_contain_text("Capturing")
    expect(page.locator("#btn-capture-toggle")).to_contain_text("Stop Capture")
    
    # Stop capture
    page.click("#btn-capture-toggle")
    expect(page.locator("#capture-status")).to_contain_text("Stopped")
    expect(page.locator("#btn-capture-toggle")).to_contain_text("Start Capture")

def test_alert_feed_updates(page, mock_pcap_path):
    """Test that importing a PCAP updates the dashboard metric cards and recent alert feeds."""
    page.goto("/")
    
    # Read initial alert count
    initial_alerts_count = page.locator("#metric-alerts").text_content()
    
    # Go to traffic tab and upload PCAP
    page.click("#tab-traffic-btn")
    page.set_input_files("#file-pcap-upload", mock_pcap_path)
    page.click("#btn-pcap-upload")
    
    # Wait for upload status to show completion
    page.wait_for_selector("#pcap-upload-status:has-text('PCAP Ingested!')")
    
    # Go back to Dashboard Overview
    page.click("#tab-dashboard-btn")
    
    # Verify alert count updated
    updated_alerts_count = page.locator("#metric-alerts").text_content()
    assert int(updated_alerts_count) > int(initial_alerts_count)
    
    # Verify recent alerts feed table has content
    recent_alerts = page.locator("#dashboard-recent-alerts tr")
    expect(recent_alerts.first).to_be_visible()

def test_ai_explainer_modal_from_ui(page):
    """Test opening and closing the AI threat explainer modal from the UI."""
    page.goto("/")
    page.click("#tab-scanner-btn")
    
    # Find the first completed scan row and click 'Explain with AI'
    explain_btn = page.locator(".btn-explain-scan").first
    expect(explain_btn).to_be_visible()
    explain_btn.click()
    
    # Verify explainer modal is shown
    modal = page.locator("#ai-explainer-modal")
    expect(modal).to_be_visible()
    
    # Verify AI text segments are loaded
    expect(page.locator("#ai-explanation")).not_to_contain_text("Thinking...")
    expect(page.locator("#ai-severity")).not_to_contain_text("Loading...")
    
    # Close the modal
    page.click("#btn-close-explainer")
    expect(modal).to_be_hidden()

def test_ui_api_500_error_boundary(page):
    """Test that the API 500 error boundary UI message is displayed when endpoints fail."""
    page.route("**/api/scans", lambda route: route.fulfill(status=500, body="Internal Server Error"))
    page.route("**/api/alerts", lambda route: route.fulfill(status=500, body="Internal Server Error"))
    page.goto("/")
    banner = page.locator("#error-boundary-banner")
    expect(banner).to_be_visible()
    expect(banner).to_contain_text("server error (500)")

def test_ui_mobile_tablet_viewports(page):
    """Test dashboard layout rendering and basic visibility checks on mobile and tablet viewports."""
    page.set_viewport_size({"width": 375, "height": 667})
    page.goto("/")
    expect(page.locator("h1:has-text('NetAgent Security Ops Center')")).to_be_visible()
    expect(page.locator("#section-dashboard")).to_be_visible()
    
    page.set_viewport_size({"width": 768, "height": 1024})
    page.goto("/")
    expect(page.locator("#section-dashboard")).to_be_visible()
    expect(page.locator("#metric-health")).to_be_visible()

def test_ui_malformed_ip_validation_error(page):
    """Test validation error prompt for malformed IPs in scan form."""
    page.goto("/")
    page.click("#tab-scanner-btn")
    page.fill("#scan-target", "999.999.999.999")
    page.click("#btn-trigger-scan")
    status = page.locator("#scan-trigger-status")
    expect(status).to_be_visible()
    expect(status).to_contain_text("Invalid IP address format")
    expect(status).to_have_class(re.compile("text-red-500"))

def test_ui_drag_drop_type_mismatch_warning(page):
    """Test that dragging and dropping a non-PCAP file shows a type mismatch warning."""
    page.goto("/")
    page.click("#tab-traffic-btn")
    drop_area = page.locator("#pcap-drop-area")
    page.evaluate(
        "(el) => { "
        "  const dt = new DataTransfer();"
        "  const file = new File(['dummy'], 'test_log.txt', {type: 'text/plain'});"
        "  dt.items.add(file);"
        "  const event = new DragEvent('drop', { dataTransfer: dt });"
        "  el.dispatchEvent(event);"
        "}",
        drop_area.element_handle()
    )
    status = page.locator("#pcap-upload-status")
    expect(status).to_be_visible()
    expect(status).to_contain_text("Only .pcap and .pcapng files are supported")

def test_ui_live_capture_start_failure(page):
    """Test live capture start failure UI notification."""
    page.goto("/")
    page.click("#tab-traffic-btn")
    page.route("**/api/alerts/capture", lambda route: route.fulfill(
        status=400,
        headers={"Content-Type": "application/json"},
        body='{"detail": "Interface eth99 does not exist"}'
    ))
    page.click("#btn-capture-toggle")
    notification = page.locator("#capture-status-notification")
    expect(notification).to_be_visible()
    expect(notification).to_contain_text("Interface eth99 does not exist")


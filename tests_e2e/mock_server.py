import os
import random
import asyncio
from datetime import datetime
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, BackgroundTasks, File, UploadFile, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(
    title="NetAgent E2E Mock Server",
    description="Mock backend server and static frontend provider for E2E Playwright validation.",
    version="1.0.0"
)

# Enable CORS for cross-origin testing if frontend and backend run on different ports
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic schemas for request bodies
class ScanRequest(BaseModel):
    target: str
    profile: str  # "quick" | "full" | "targeted"

class CaptureRequest(BaseModel):
    action: str  # "start" | "stop"
    interface: Optional[str] = None

class ExplainRequest(BaseModel):
    source_type: str  # "scan" | "alert"
    source_id: int

# In-memory Mock Database
class MockDatabase:
    def __init__(self):
        self.scans: Dict[int, Dict[str, Any]] = {}
        self.alerts: List[Dict[str, Any]] = []
        self.scan_id_counter = 1
        self.alert_id_counter = 1
        
        self.capture_active = False
        self.capture_interface: Optional[str] = None
        self.capture_task: Optional[asyncio.Task] = None
        
        self.seed_initial_data()

    def seed_initial_data(self):
        # Seed two historical scans
        self.scans[self.scan_id_counter] = {
            "id": self.scan_id_counter,
            "target": "192.168.1.1",
            "profile": "quick",
            "status": "completed",
            "created_at": "2026-06-10T01:30:00Z",
            "completed_at": "2026-06-10T01:30:05Z",
            "results": {
                "ports": [
                    {"port": 80, "service": "http", "state": "open", "vulnerabilities": []},
                    {"port": 443, "service": "https", "state": "open", "vulnerabilities": []}
                ]
            }
        }
        self.scan_id_counter += 1
        
        self.scans[self.scan_id_counter] = {
            "id": self.scan_id_counter,
            "target": "10.0.0.1",
            "profile": "full",
            "status": "completed",
            "created_at": "2026-06-10T01:32:00Z",
            "completed_at": "2026-06-10T01:32:15Z",
            "results": {
                "ports": [
                    {"port": 22, "service": "ssh", "state": "open", "vulnerabilities": []},
                    {"port": 80, "service": "http", "state": "open", "vulnerabilities": ["CVE-2021-41773"]},
                    {"port": 8080, "service": "http-alt", "state": "open", "vulnerabilities": ["CVE-2024-XXXX"]}
                ]
            }
        }
        self.scan_id_counter += 1

        # Seed initial alerts
        self.alerts.append({
            "id": self.alert_id_counter,
            "timestamp": "2026-06-10T01:32:10Z",
            "source_ip": "10.0.0.50",
            "destination_ip": "10.0.0.1",
            "protocol": "TCP",
            "alert_type": "Port Scan",
            "description": "Suspicious scan activity on ports 22, 80, 8080",
            "severity": "medium"
        })
        self.alert_id_counter += 1

db = MockDatabase()

# Background task to transition scan state from running to completed
async def simulate_scan_completion(scan_id: int, target: str, profile: str):
    # Simulate scanning time based on profile
    scan_duration = 5 if profile == "full" else 2
    await asyncio.sleep(scan_duration)
    
    if scan_id in db.scans:
        db.scans[scan_id]["status"] = "completed"
        db.scans[scan_id]["completed_at"] = datetime.utcnow().isoformat() + "Z"
        
        # Determine ports and services based on profile
        if profile == "quick":
            ports = [
                {"port": 80, "service": "http", "state": "open", "vulnerabilities": []},
                {"port": 22, "service": "ssh", "state": "open", "vulnerabilities": []}
            ]
        elif profile == "full":
            ports = [
                {"port": 80, "service": "http", "state": "open", "vulnerabilities": ["CVE-2021-41773"]},
                {"port": 22, "service": "ssh", "state": "open", "vulnerabilities": []},
                {"port": 443, "service": "https", "state": "open", "vulnerabilities": []},
                {"port": 8080, "service": "http-alt", "state": "open", "vulnerabilities": ["CVE-2024-XXXX"]}
            ]
        else:  # targeted
            ports = [
                {"port": 80, "service": "http", "state": "open", "vulnerabilities": []}
            ]
            
        db.scans[scan_id]["results"] = {
            "ports": ports
        }

# Background task to generate alerts during active live packet sniffing
async def generate_live_alerts_loop():
    try:
        while db.capture_active:
            await asyncio.sleep(3)  # Add a mock alert every 3 seconds
            if not db.capture_active:
                break
                
            alert_types = [
                ("Port Scan", "medium", "TCP SYN scan detected from external source"),
                ("DDoS Attack", "critical", "SYN flood threshold exceeded: 10000 pps"),
                ("Brute Force SSH", "high", "Multiple failed login attempts on port 22"),
                ("DNS Query Tunneling", "low", "Abnormal TXT payload volume detected in queries")
            ]
            alert_type, severity, description = random.choice(alert_types)
            
            new_alert = {
                "id": db.alert_id_counter,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "source_ip": f"192.168.1.{random.randint(2, 254)}",
                "destination_ip": "192.168.1.100",
                "protocol": "TCP" if alert_type != "DNS Query Tunneling" else "UDP",
                "alert_type": alert_type,
                "description": description,
                "severity": severity
            }
            db.alerts.append(new_alert)
            db.alert_id_counter += 1
    except asyncio.CancelledError:
        pass

# --- ROUTE: Front-end Provider ---

@app.get("/", response_class=HTMLResponse)
async def serve_mock_frontend():
    # Attempt to load from current directory first (production layout)
    frontend_path = os.path.join(os.path.dirname(__file__), "mock_frontend.html")
    if os.path.exists(frontend_path):
        with open(frontend_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
            
    # Fallback to agent workspace location if running inside Agent environment
    agent_path = "/home/sarthak/Documents/netagent/.agents/explorer_e1_3/proposed_mock_frontend.html"
    if os.path.exists(agent_path):
        with open(agent_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
            
    # Inline basic fallback template if no file exists
    fallback_html = """
    <!DOCTYPE html>
    <html>
    <head><title>NetAgent Mock</title></head>
    <body style="font-family: sans-serif; padding: 2rem; background: #f3f4f6;">
        <h1>NetAgent Mock Frontend</h1>
        <p style="color: #ef4444; font-weight: bold;">Warning: mock_frontend.html not found on disk.</p>
        <p>Please ensure proposed_mock_frontend.html is copied to tests_e2e/mock_frontend.html</p>
    </body>
    </html>
    """
    return HTMLResponse(content=fallback_html)

# --- ROUTES: 1. Active Scan Endpoints ---

@app.post("/api/scans", status_code=201)
async def create_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    # 1. Empty/missing target check
    if not request.target or not request.target.strip():
        raise HTTPException(status_code=400, detail="Target is required")
        
    # 2. Very long string injection check (> 256 characters)
    if len(request.target) > 256 or len(request.profile) > 256:
        raise HTTPException(status_code=400, detail="Input string exceeds maximum allowed length")
        
    # 3. Invalid IP format validation
    def is_valid_ip(ip: str) -> bool:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            if not part.isdigit():
                return False
            val = int(part)
            if val < 0 or val > 255:
                return False
        return True
        
    if not is_valid_ip(request.target):
        raise HTTPException(status_code=400, detail="Invalid IP address format")
        
    # 4. Invalid scan profile check
    if request.profile not in ("quick", "full", "targeted"):
        raise HTTPException(status_code=400, detail="Invalid scan profile")

    scan_id = db.scan_id_counter
    db.scan_id_counter += 1
    
    new_scan = {
        "id": scan_id,
        "target": request.target,
        "profile": request.profile,
        "status": "running",
        "created_at": datetime.utcnow().isoformat() + "Z"
    }
    db.scans[scan_id] = new_scan
    
    # Queue the background simulation task to finish the scan
    background_tasks.add_task(simulate_scan_completion, scan_id, request.target, request.profile)
    
    return new_scan


@app.get("/api/scans")
async def get_scans():
    # Return as list, sorted by ID ascending
    return list(db.scans.values())

@app.get("/api/scans/{scan_id}")
async def get_scan_details(scan_id: int):
    if scan_id not in db.scans:
        raise HTTPException(status_code=404, detail="Scan result not found")
    return db.scans[scan_id]

# --- ROUTES: 2. Passive Traffic Endpoints ---

@app.post("/api/alerts/capture")
async def control_capture(request: CaptureRequest):
    if not request.action or not request.action.strip():
        raise HTTPException(status_code=400, detail="Action is required")
        
    action = request.action.lower()
    
    if action == "start":
        if not request.interface:
            raise HTTPException(status_code=400, detail="Interface required to start capture")
        
        valid_interfaces = {"eth0", "wlan0", "lo"}
        if request.interface not in valid_interfaces:
            raise HTTPException(status_code=400, detail=f"Interface {request.interface} does not exist")
        
        if db.capture_active:
            return {"status": "capturing", "interface": db.capture_interface, "message": "Capture already running"}
            
        db.capture_active = True
        db.capture_interface = request.interface
        # Start background alerts generator loop
        db.capture_task = asyncio.create_task(generate_live_alerts_loop())
        
        return {"status": "capturing", "interface": db.capture_interface}
        
    elif action == "stop":
        if not db.capture_active:
            return {"status": "stopped", "message": "Capture already stopped"}
            
        db.capture_active = False
        db.capture_interface = None
        if db.capture_task:
            db.capture_task.cancel()
            db.capture_task = None
            
        return {"status": "stopped"}
        
    else:
        raise HTTPException(status_code=400, detail="Invalid action. Use 'start' or 'stop'")

@app.post("/api/alerts/analyze-pcap")
async def analyze_pcap(file: UploadFile = File(...)):
    filename = file.filename.lower() if file.filename else "unknown.pcap"
    
    # 1. Basic validation of pcap file extension
    if not (filename.endswith(".pcap") or filename.endswith(".pcapng")):
        raise HTTPException(status_code=400, detail="Only .pcap and .pcapng files are supported")
        
    # 2. Invalid content-type upload
    if file.content_type and file.content_type not in (
        "application/octet-stream",
        "application/vnd.tcpdump.pcap",
        "application/x-pcap",
    ):
        raise HTTPException(status_code=400, detail="Unsupported Content-Type")
        
    content = await file.read()
    
    # 3. Zero-byte file upload
    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Empty PCAP file uploaded")
        
    # 4. Corrupt binary file upload
    if b"corrupt" in content or "corrupt" in filename:
        raise HTTPException(status_code=400, detail="Corrupt PCAP file structure")
        
    # 5. Excessively large file simulation (> 50MB or "large" in name)
    if len(content) > 50 * 1024 * 1024 or "large" in filename:
        raise HTTPException(status_code=413, detail="File size exceeds limit")
        
    # Simulate processing delay
    await asyncio.sleep(1.5)
    
    generated_alerts = []
    
    # Custom mock generator matching target scenario patterns
    if "ddos" in filename:
        alerts_pool = [
            ("DDoS Attack", "critical", "SYN flood threshold exceeded: 12000 pps"),
            ("Anomaly", "high", "High volume of UDP packet flow detected")
        ]
    elif "scan" in filename:
        alerts_pool = [
            ("Port Scan", "medium", "XMAS scan pattern identified on target host"),
            ("OS Fingerprinting", "low", "Nmap OS detection signature triggered")
        ]
    else:
        # Generic fallback alerts
        alerts_pool = [
            ("Suspicious Traffic", "medium", f"Ingested alert from PCAP file: {file.filename}")
        ]
        
    for alert_type, severity, description in alerts_pool:
        new_alert = {
            "id": db.alert_id_counter,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "source_ip": "10.0.0.99",
            "destination_ip": "192.168.1.1",
            "protocol": "TCP",
            "alert_type": alert_type,
            "description": description,
            "severity": severity
        }
        db.alerts.append(new_alert)
        generated_alerts.append(new_alert)
        db.alert_id_counter += 1
        
    return {
        "status": "success",
        "filename": file.filename,
        "alerts_generated": len(generated_alerts),
        "alerts": generated_alerts
    }

@app.get("/api/alerts")
async def get_alerts(limit: Optional[int] = None, severity: Optional[str] = None):
    alerts = db.alerts
    if severity:
        alerts = [a for a in alerts if a["severity"].lower() == severity.lower()]
    if limit is not None:
        if limit < 0:
            raise HTTPException(status_code=400, detail="Limit must be non-negative")
        alerts = alerts[-limit:]
    return alerts

# --- ROUTES: 3. AI Explanation Endpoints ---

@app.post("/api/explain")
async def explain_threat(request_data: ExplainRequest, request: Request):
    if request.headers.get("x-simulate-ollama-offline") == "true" or request_data.source_id == 503:
        raise HTTPException(status_code=503, detail="Ollama service offline. Fallback explanation not available.")
        
    source_type = request_data.source_type.lower()
    source_id = request_data.source_id
    
    if source_id < 0:
        raise HTTPException(status_code=400, detail="Source ID cannot be negative")
        
    if source_type not in ("scan", "alert"):
        raise HTTPException(status_code=400, detail="Invalid source_type. Use 'scan' or 'alert'")
        
    if source_type == "scan":
        # Search scan in our database
        if source_id not in db.scans:
            raise HTTPException(status_code=404, detail="Scan not found")
        scan = db.scans[source_id]
        
        # Formulate custom explanations based on found ports
        results = scan.get("results", {})
        ports_list = results.get("ports", [])
        
        vulnerabilities = []
        for port_info in ports_list:
            vulns = port_info.get("vulnerabilities", [])
            vulnerabilities.extend(vulns)
            
        if vulnerabilities:
            explanation = (
                f"Active scan against {scan['target']} using {scan['profile']} profile discovered "
                f"critical security flaws. Vulnerabilities detected: {', '.join(vulnerabilities)}. "
                "These vulnerabilities allow remote attackers to bypass authorization controls, execute "
                "arbitrary scripts, or trigger buffer overflow conditions on your open services."
            )
            severity = "critical"
            remediation = (
                "1. Apply latest patches to affected server components immediately.\n"
                "2. Disable unused services (e.g. HTTP-alt on port 8080).\n"
                "3. Enforce network segmentation rules to isolate the target machine."
            )
        else:
            explanation = (
                f"Active scan against {scan['target']} completed. Discovered open ports: "
                f"{', '.join([str(p['port']) for p in ports_list])}. No signature-matching vulnerabilities "
                "were found in current repository definitions. However, leaving administrative ports open "
                "increases host attack surface."
            )
            severity = "low"
            remediation = (
                "1. Implement strict firewall access control lists (ACLs).\n"
                "2. Enforce strong multi-factor authentication (MFA) for services like SSH (22)."
            )
            
    elif source_type == "alert":
        # Search alert in database
        matching_alert = next((a for a in db.alerts if a["id"] == source_id), None)
        if not matching_alert:
            raise HTTPException(status_code=404, detail="Alert not found")
            
        alert_type = matching_alert["alert_type"]
        description = matching_alert["description"]
        
        if "ddos" in alert_type.lower():
            explanation = (
                f"The system detected a potential Distributed Denial of Service (DDoS) incident "
                f"({alert_type}). Description: {description}. Multiple network endpoints are flooding "
                "the target with high packet volume, causing resource exhaustion and potential outage."
            )
            severity = "critical"
            remediation = (
                "1. Enable upstream rate-limiting policies at edge firewalls.\n"
                "2. Route traffic through a content delivery network (CDN) or dedicated DDoS mitigation provider.\n"
                "3. Configure connection timeouts to release resources more aggressively."
            )
        elif "port scan" in alert_type.lower():
            explanation = (
                f"Reconnaissance sweep detected: {alert_type}. Description: {description}. "
                "An attacker is probes ports to map out active services and prepare targeted exploit campaigns."
            )
            severity = "medium"
            remediation = (
                "1. Deploy port scanning detection rules (e.g. fail2ban, Snort).\n"
                "2. Block offending IP addresses using ingress firewalls.\n"
                "3. Secure or close unnecessary open ports."
            )
        else:
            explanation = (
                f"Security event triggered: {alert_type}. Description: {description}. "
                "This behavior deviates from normal baseline traffic profiles and represents an intrusion risk."
            )
            severity = matching_alert["severity"]
            remediation = (
                "1. Review system and application logs on the target host.\n"
                "2. Verify host baseline file integrity.\n"
                "3. Perform deep inspection on packet payloads using Wireshark."
            )
            
    else:
        raise HTTPException(status_code=400, detail="Invalid source_type. Use 'scan' or 'alert'")
        
    return {
        "explanation": explanation,
        "severity": severity,
        "remediation": remediation
    }

# --- Entrypoint wrapper ---
if __name__ == "__main__":
    import uvicorn
    # Default port for test backend, can be run on port 8080/8000/5000 as configured in tests
    uvicorn.run(app, host="127.0.0.1", port=8000)

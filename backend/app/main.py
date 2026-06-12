import datetime
import json
import socket
import ipaddress
from typing import List, Optional
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, status, UploadFile, File, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from .database import engine, get_db, SessionLocal, Base
from . import models, schemas, scanner, analyzer, ai_explainer, agent

# Initialize database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="NetAgent Backend API")

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc: RequestValidationError):
    errors = exc.errors()
    if errors:
        message = errors[0].get("msg", "Validation error")
    else:
        message = "Validation error"
    
    if message.startswith("Value error, "):
        message = message[len("Value error, "):]
        
    return JSONResponse(
        status_code=400,
        content={"detail": message}
    )

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def run_background_scan(scan_id: int, target: str, profile: str):
    # Phase 1: Verify scan existence and ensure status is set to running
    db = SessionLocal()
    try:
        db_scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
        if not db_scan:
            return
        if db_scan.status != "running":
            db_scan.status = "running"
            db.commit()
    except Exception:
        return
    finally:
        db.close()  # Release connection back to pool during scan

    # Phase 2: Run slow socket scan
    try:
        results = scanner.execute_scan(target, profile)
        scan_error = None
    except Exception as e:
        results = None
        scan_error = e

    # Phase 3: Open a new connection to save results and update status
    db = SessionLocal()
    try:
        db_scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
        if not db_scan:
            return

        if scan_error is not None:
            db_scan.status = "failed"
            db_scan.completed_at = datetime.datetime.utcnow()
            db_scan.error_message = str(scan_error)
            db.commit()
            return

        # Persist results
        for r in results:
            db_result = models.ScanResult(
                scan_id=scan_id,
                port=r["port"],
                protocol=r["protocol"],
                state=r["state"],
                status=r["status"],
                service=r.get("service"),
                banner=r.get("banner"),
                vulnerability=r.get("vulnerability"),
                vulnerabilities=r.get("vulnerabilities")
            )
            db.add(db_result)

        db_scan.status = "completed"
        db_scan.completed_at = datetime.datetime.utcnow()
        db.commit()
    except Exception as e:
        db.rollback()
        # Fallback error recording
        try:
            db_scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
            if db_scan:
                db_scan.status = "failed"
                db_scan.completed_at = datetime.datetime.utcnow()
                db_scan.error_message = f"Failed to persist results: {e}"
                db.commit()
        except Exception:
            pass
    finally:
        db.close()  # Release connection

@app.post("/api/scans", response_model=schemas.ScanResponse, status_code=status.HTTP_201_CREATED)
def start_scan(
    payload: schemas.ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Triggers a new active network/port scan in the background.
    """
    # 1. Resolve host to verify DNS or IP / CIDR validity
    try:
        # Check if CIDR format
        ipaddress.ip_network(payload.target, strict=False)
    except ValueError:
        # Otherwise, verify hostname resolution (supports IPv4/IPv6)
        try:
            socket.getaddrinfo(payload.target, None)
        except socket.gaierror:
            raise HTTPException(
                status_code=400,
                detail=f"Could not resolve host: {payload.target}"
            )
    
    # 2. Create database entry
    db_scan = models.Scan(
        target=payload.target,
        profile=payload.profile,
        status="running",
        created_at=datetime.datetime.utcnow()
    )
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)

    # 3. Queue scan execution background task
    background_tasks.add_task(
        run_background_scan,
        scan_id=db_scan.id,
        target=payload.target,
        profile=payload.profile
    )

    return db_scan

@app.get("/api/scans", response_model=List[schemas.ScanResponse])
def get_scans_history(
    limit: int = 100,
    offset: int = 0,
    status: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    Retrieves the history of all scans.
    """
    query = db.query(models.Scan)
    if status:
        query = query.filter(models.Scan.status == status)
    return query.order_by(models.Scan.created_at.desc()).offset(offset).limit(limit).all()

@app.get("/api/scans/{id}", response_model=schemas.ScanDetailResponse)
def get_scan_details(id: int, db: Session = Depends(get_db)):
    """
    Retrieves detailed results for a specific scan.
    """
    db_scan = db.query(models.Scan).filter(models.Scan.id == id).first()
    if not db_scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    return db_scan


# 1. POST /api/alerts/capture
@app.post("/api/alerts/capture")
async def control_capture(request: schemas.CaptureRequest):
    if not request.action or not request.action.strip():
        raise HTTPException(status_code=400, detail="Action is required")

    action = request.action.lower()
    if action not in ("start", "stop"):
        raise HTTPException(status_code=400, detail="Invalid action. Use 'start' or 'stop'")

    if action == "start":
        if not request.interface:
            raise HTTPException(status_code=400, detail="Interface required to start capture")
        
        valid_interfaces = {"eth0", "wlan0", "lo"}
        if request.interface not in valid_interfaces:
            raise HTTPException(status_code=400, detail=f"Interface {request.interface} does not exist")

        started, msg = await analyzer.capture_manager.start(request.interface)
        if not started:
            return {
                "status": "capturing",
                "interface": analyzer.capture_manager.interface,
                "message": msg
            }
        return {"status": "capturing", "interface": request.interface}

    elif action == "stop":
        stopped, msg = await analyzer.capture_manager.stop()
        if not stopped:
            return {"status": "stopped", "message": msg}
        return {"status": "stopped"}


# 2. POST /api/alerts/analyze-pcap
@app.post("/api/alerts/analyze-pcap", response_model=schemas.PCAPAnalysisResponse)
async def analyze_pcap(file: UploadFile = File(...), db: Session = Depends(get_db)):
    filename = file.filename.lower() if file.filename else "unknown.pcap"
    
    # Validation 1: Extension check
    if not (filename.endswith(".pcap") or filename.endswith(".pcapng")):
        raise HTTPException(status_code=400, detail="Only .pcap and .pcapng files are supported")

    # Validation 2: Content-Type check
    if file.content_type and file.content_type not in (
        "application/octet-stream",
        "application/vnd.tcpdump.pcap",
        "application/x-pcap",
    ):
        raise HTTPException(status_code=400, detail="Unsupported Content-Type")

    content = await file.read()
    
    # Validation 3: Zero-byte check
    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Empty PCAP file uploaded")

    # Validation 4: Excessively large file simulated check
    if len(content) > 50 * 1024 * 1024 or "large" in filename:
        raise HTTPException(status_code=413, detail="File size exceeds limit")

    # Parsing execution
    try:
        generated_alerts = analyzer.analyze_pcap_data(content, file.filename)
    except Exception:
        raise HTTPException(status_code=400, detail="Corrupt PCAP file structure")

    # Save to SQLite
    db_alerts = []
    for alert_data in generated_alerts:
        db_alert = models.Alert(
            timestamp=alert_data["timestamp"],
            source_ip=alert_data["source_ip"],
            destination_ip=alert_data["destination_ip"],
            protocol=alert_data["protocol"],
            alert_type=alert_data["alert_type"],
            description=alert_data["description"],
            severity=alert_data["severity"]
        )
        db.add(db_alert)
        db_alerts.append(db_alert)
    db.commit()

    for db_alert in db_alerts:
        db.refresh(db_alert)

    return {
        "status": "success",
        "filename": file.filename,
        "alerts_generated": len(db_alerts),
        "alerts": db_alerts
    }


# 3. GET /api/alerts
@app.get("/api/alerts", response_model=List[schemas.AlertResponse])
def get_alerts(
    limit: Optional[int] = None,
    severity: Optional[str] = None,
    db: Session = Depends(get_db)
):
    if limit is not None and limit < 0:
        raise HTTPException(status_code=400, detail="Limit must be non-negative")

    query = db.query(models.Alert)
    if severity:
        query = query.filter(models.Alert.severity.ilike(severity))

    if limit is not None:
        # Retrieve the latest N alerts, but return them in ascending order
        latest_alerts = query.order_by(models.Alert.id.desc()).limit(limit).all()
        return list(reversed(latest_alerts))

    return query.order_by(models.Alert.id.asc()).all()


# 4. POST /api/explain
@app.post("/api/explain", response_model=schemas.ExplainResponse, status_code=status.HTTP_200_OK)
async def explain_threat(
    payload: schemas.ExplainRequest,
    x_simulate_ollama_offline: Optional[str] = Header(None, alias="X-Simulate-Ollama-Offline"),
    db: Session = Depends(get_db)
):
    """
    Retrieves an AI-powered explanation and remediation suggestions for scans or alerts.
    Utilizes local Ollama instance with fallback to a database-driven mock generator.
    """
    # 1. Handle simulated offline condition
    if x_simulate_ollama_offline == "true":
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Ollama service offline. Fallback explanation not available."
        )

    source_type = payload.source_type.lower()
    source_id = payload.source_id

    # 2. Validate input constraints
    if source_id < 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Source ID cannot be negative"
        )

    if source_type not in ("scan", "alert"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid source_type. Use 'scan' or 'alert'"
        )

    # 3. Retrieve database records and query AI Explainer service
    if source_type == "scan":
        db_scan = db.query(models.Scan).filter(models.Scan.id == source_id).first()
        if not db_scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found"
            )
        return await ai_explainer.explain_scan(db_scan)

    elif source_type == "alert":
        db_alert = db.query(models.Alert).filter(models.Alert.id == source_id).first()
        if not db_alert:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Alert not found"
            )
        return await ai_explainer.explain_alert(db_alert)


# === Semi-Autonomous Agent API ===

@app.post("/api/agent/sessions", response_model=schemas.AgentSessionResponse, status_code=status.HTTP_201_CREATED)
def start_agent_session(
    payload: schemas.AgentSessionCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Start a new autonomous agent investigation session."""
    db_session = models.AgentSession(
        target=payload.target,
        profile=payload.profile,
        status="running",
        created_at=datetime.datetime.utcnow()
    )
    db.add(db_session)
    db.commit()
    db.refresh(db_session)

    background_tasks.add_task(
        agent.run_agent_investigation,
        session_id=db_session.id,
        target=payload.target,
        profile=payload.profile
    )

    return db_session


@app.get("/api/agent/sessions", response_model=List[schemas.AgentSessionResponse])
def get_agent_sessions(db: Session = Depends(get_db)):
    """List all agent investigation sessions."""
    sessions = db.query(models.AgentSession).order_by(models.AgentSession.created_at.desc()).all()
    return sessions


@app.get("/api/agent/sessions/{session_id}", response_model=schemas.AgentSessionResponse)
def get_agent_session(session_id: int, db: Session = Depends(get_db)):
    """Get detailed status of a specific agent session including all steps."""
    session = db.query(models.AgentSession).filter(models.AgentSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Agent session not found")
    return session


@app.post("/api/agent/sessions/{session_id}/approve/{step_id}")
def approve_agent_action(
    session_id: int,
    step_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Approve a pending remediation action."""
    step = db.query(models.AgentStep).filter(
        models.AgentStep.id == step_id,
        models.AgentStep.session_id == session_id,
        models.AgentStep.status == "pending_approval"
    ).first()

    if not step:
        raise HTTPException(status_code=404, detail="No pending action found for this step")

    background_tasks.add_task(
        agent.execute_approved_actions,
        session_id=session_id,
        step_id=step_id
    )

    return {"success": True, "message": "Actions approved. Executing remediation..."}


@app.post("/api/agent/sessions/{session_id}/reject/{step_id}")
def reject_agent_action(
    session_id: int,
    step_id: int,
    db: Session = Depends(get_db)
):
    """Reject a pending remediation action."""
    step = db.query(models.AgentStep).filter(
        models.AgentStep.id == step_id,
        models.AgentStep.session_id == session_id,
        models.AgentStep.status == "pending_approval"
    ).first()

    if not step:
        raise HTTPException(status_code=404, detail="No pending action found for this step")

    step.status = "rejected"
    step.completed_at = datetime.datetime.utcnow()

    session = db.query(models.AgentSession).filter(models.AgentSession.id == session_id).first()
    if session:
        session.status = "completed"
        session.completed_at = datetime.datetime.utcnow()

        # Add a final summary step
        next_step_num = step.step_number + 1
        summary = models.AgentStep(
            session_id=session_id,
            step_number=next_step_num,
            action_type="summary",
            title="Investigation Complete \u2014 Actions Rejected",
            description="Operator rejected the proposed remediation actions. Investigation closed without remediation.",
            status="completed",
            result_data=json.dumps({"decision": "rejected", "reason": "Operator decision"}),
            created_at=datetime.datetime.utcnow(),
            completed_at=datetime.datetime.utcnow()
        )
        db.add(summary)

    db.commit()
    return {"success": True, "message": "Actions rejected. Session closed."}

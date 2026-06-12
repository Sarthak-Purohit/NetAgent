import datetime
import json
import logging
import asyncio
from typing import Optional
from sqlalchemy.orm import Session
from .database import SessionLocal
from . import models, scanner, ai_explainer

logger = logging.getLogger("netagent.agent")


def _add_step(db: Session, session_id: int, step_number: int, action_type: str,
              title: str, description: str = None, status: str = "running",
              result_data: str = None) -> models.AgentStep:
    step = models.AgentStep(
        session_id=session_id,
        step_number=step_number,
        action_type=action_type,
        title=title,
        description=description,
        status=status,
        result_data=result_data,
        created_at=datetime.datetime.utcnow()
    )
    db.add(step)
    db.commit()
    db.refresh(step)
    return step


def _complete_step(db: Session, step: models.AgentStep, result_data: str = None):
    step.status = "completed"
    step.completed_at = datetime.datetime.utcnow()
    if result_data:
        step.result_data = result_data
    db.commit()


def _generate_remediation_actions(scan_results: list, ai_response: dict, target: str) -> list:
    """Generate specific remediation actions based on scan results and AI analysis."""
    actions = []
    severity = ai_response.get("severity", "low")

    # Analyze open ports for risky services
    risky_ports = []
    for r in scan_results:
        port = r.get("port", 0)
        service = r.get("service", "unknown")
        vulns = r.get("vulnerabilities") or r.get("vulnerability")

        if vulns:
            actions.append({
                "action_id": f"patch_{port}",
                "type": "patch_service",
                "title": f"Patch vulnerable service on port {port}",
                "description": f"Apply security patches for {service} (port {port}). Detected: {vulns}",
                "command": f"# Check for updates: sudo apt-get update && sudo apt-get upgrade {service}",
                "risk": "low",
                "port": port
            })

        if port in [21, 23]:  # Insecure protocols
            actions.append({
                "action_id": f"block_{port}",
                "type": "block_port",
                "title": f"Block insecure port {port} ({service})",
                "description": f"Port {port} ({service}) uses an insecure plaintext protocol. Blocking it prevents credential theft.",
                "command": f"sudo iptables -A INPUT -p tcp --dport {port} -j DROP",
                "risk": "medium",
                "port": port
            })
            risky_ports.append(port)

        if port in [3306, 5432] and severity in ["high", "critical"]:  # Exposed databases
            actions.append({
                "action_id": f"restrict_{port}",
                "type": "restrict_access",
                "title": f"Restrict access to database port {port}",
                "description": f"Database service {service} on port {port} is exposed to the network. Restrict to localhost only.",
                "command": f"sudo iptables -A INPUT -p tcp --dport {port} ! -s 127.0.0.1 -j DROP",
                "risk": "medium",
                "port": port
            })

        if port == 3389:  # RDP
            actions.append({
                "action_id": f"restrict_{port}",
                "type": "restrict_access",
                "title": f"Restrict RDP access on port {port}",
                "description": "Remote Desktop Protocol exposed. Restrict to VPN-only access.",
                "command": f"sudo iptables -A INPUT -p tcp --dport {port} ! -s 10.0.0.0/8 -j DROP",
                "risk": "high",
                "port": port
            })

    # Always add a general hardening action if severity is high/critical
    if severity in ["high", "critical"]:
        actions.append({
            "action_id": "enable_ids",
            "type": "enable_monitoring",
            "title": "Enable enhanced IDS monitoring",
            "description": f"Deploy intrusion detection rules for {target} to monitor for exploitation attempts.",
            "command": f"# Enable enhanced monitoring: snort -A alert_fast -c /etc/snort/snort.conf -i eth0",
            "risk": "low"
        })

    if not actions:
        actions.append({
            "action_id": "no_action",
            "type": "informational",
            "title": "No immediate remediation required",
            "description": "The scan found open ports but no critical vulnerabilities. Continue monitoring.",
            "command": "# No action needed",
            "risk": "none"
        })

    return actions


def run_agent_investigation(session_id: int, target: str, profile: str):
    """Main agent investigation loop. Runs in a background thread."""
    db = SessionLocal()
    current_step = 0

    try:
        session = db.query(models.AgentSession).filter(models.AgentSession.id == session_id).first()
        if not session:
            return

        # === STEP 1: Initialization ===
        current_step += 1
        step1 = _add_step(db, session_id, current_step, "initialize",
                         "Initializing Investigation",
                         f"Starting autonomous security investigation of {target} using {profile} scan profile.")
        _complete_step(db, step1, json.dumps({"target": target, "profile": profile}))

        # === STEP 2: Active Port Scan ===
        current_step += 1
        step2 = _add_step(db, session_id, current_step, "scan",
                         f"Active Port Scan ({profile.title()})",
                         f"Scanning {target} for open ports, services, and banners...")

        try:
            scan_results = scanner.execute_scan(target, profile)
        except Exception as e:
            step2.status = "failed"
            step2.result_data = json.dumps({"error": str(e)})
            step2.completed_at = datetime.datetime.utcnow()
            session.status = "failed"
            db.commit()
            return

        scan_summary = []
        for r in scan_results:
            scan_summary.append({
                "port": r["port"],
                "protocol": r["protocol"],
                "service": r.get("service", "unknown"),
                "banner": r.get("banner"),
                "vulnerability": r.get("vulnerability")
            })

        _complete_step(db, step2, json.dumps({
            "ports_found": len(scan_results),
            "results": scan_summary
        }))

        # Also persist scan to the main Scans table for cross-referencing
        db_scan = models.Scan(
            target=target,
            profile=profile,
            status="completed",
            created_at=datetime.datetime.utcnow(),
            completed_at=datetime.datetime.utcnow()
        )
        db.add(db_scan)
        db.commit()
        db.refresh(db_scan)

        for r in scan_results:
            db_result = models.ScanResult(
                scan_id=db_scan.id,
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
        db.commit()

        # === STEP 3: AI Threat Analysis ===
        current_step += 1
        step3 = _add_step(db, session_id, current_step, "explain",
                         "AI Threat Analysis",
                         "Querying local LLM (Ollama/Llama2) to analyze scan findings...")

        # Need to run the async AI explainer in a sync context
        db.refresh(db_scan)
        loop = asyncio.new_event_loop()
        try:
            ai_response = loop.run_until_complete(ai_explainer.explain_scan(db_scan))
        finally:
            loop.close()

        _complete_step(db, step3, json.dumps(ai_response))

        ai_severity = ai_response.get("severity", "low")

        # === STEP 4: Deep Investigation (conditional) ===
        if ai_severity in ["critical", "high"] and profile == "quick":
            current_step += 1
            step4 = _add_step(db, session_id, current_step, "investigate",
                             "Deep Investigation Scan",
                             f"Severity is {ai_severity.upper()}. Escalating to full port scan for comprehensive coverage...")

            try:
                deep_results = scanner.execute_scan(target, "full")
            except Exception as e:
                step4.status = "completed"
                step4.result_data = json.dumps({"note": f"Deep scan skipped due to error: {e}", "fallback": True})
                step4.completed_at = datetime.datetime.utcnow()
                db.commit()
                deep_results = scan_results  # Fall back to original results
            else:
                # Merge findings
                existing_ports = {r["port"] for r in scan_results}
                new_findings = [r for r in deep_results if r["port"] not in existing_ports]
                scan_results.extend(new_findings)

                _complete_step(db, step4, json.dumps({
                    "additional_ports_found": len(new_findings),
                    "total_ports": len(scan_results),
                    "note": "Full scan completed. Merged with initial findings."
                }))

            # Re-analyze with deeper results
            current_step += 1
            step4b = _add_step(db, session_id, current_step, "explain",
                              "Updated AI Threat Assessment",
                              "Re-analyzing expanded scan results with AI...")

            # Create a temporary scan record for the deep results for AI analysis
            db_deep_scan = models.Scan(
                target=target, profile="full", status="completed",
                created_at=datetime.datetime.utcnow(),
                completed_at=datetime.datetime.utcnow()
            )
            db.add(db_deep_scan)
            db.commit()
            db.refresh(db_deep_scan)

            for r in scan_results:
                db_r = models.ScanResult(
                    scan_id=db_deep_scan.id, port=r["port"],
                    protocol=r.get("protocol", "TCP"), state=r.get("state", "open"),
                    status=r.get("status", "open"), service=r.get("service"),
                    banner=r.get("banner"), vulnerability=r.get("vulnerability"),
                    vulnerabilities=r.get("vulnerabilities")
                )
                db.add(db_r)
            db.commit()
            db.refresh(db_deep_scan)

            loop = asyncio.new_event_loop()
            try:
                ai_response = loop.run_until_complete(ai_explainer.explain_scan(db_deep_scan))
            finally:
                loop.close()

            _complete_step(db, step4b, json.dumps(ai_response))
            ai_severity = ai_response.get("severity", "low")

        elif ai_severity in ["critical", "high"]:
            # Already did a full/targeted scan, just log the severity assessment
            current_step += 1
            step4 = _add_step(db, session_id, current_step, "investigate",
                             "Risk Assessment",
                             f"Severity is {ai_severity.upper()}. Current scan profile is sufficient for assessment.")
            _complete_step(db, step4, json.dumps({"severity": ai_severity, "note": "No escalation needed, scan already comprehensive."}))

        else:
            # Medium or low severity
            current_step += 1
            step4 = _add_step(db, session_id, current_step, "investigate",
                             "Risk Assessment",
                             f"Severity assessed as {ai_severity.upper()}. Proceeding with standard evaluation.")
            _complete_step(db, step4, json.dumps({"severity": ai_severity, "assessment": "Standard risk level"}))

        # === STEP 5: Propose Remediation Actions ===
        current_step += 1
        remediation_actions = _generate_remediation_actions(scan_results, ai_response, target)

        # If all actions are informational (low risk, no action needed), complete session
        has_actionable = any(a["type"] != "informational" for a in remediation_actions)

        if has_actionable:
            step5 = _add_step(db, session_id, current_step, "remediate",
                             "Proposed Remediation Actions",
                             f"Agent has identified {len(remediation_actions)} remediation action(s). Awaiting operator approval.",
                             status="pending_approval",
                             result_data=json.dumps({"actions": remediation_actions, "ai_remediation": ai_response.get("remediation", "")}))

            session.status = "awaiting_approval"
            db.commit()
            logger.info(f"Agent session {session_id} paused — awaiting operator approval for {len(remediation_actions)} action(s).")
        else:
            step5 = _add_step(db, session_id, current_step, "remediate",
                             "Investigation Complete — No Action Required",
                             "No critical remediation actions identified. Target appears secure.",
                             result_data=json.dumps({"actions": remediation_actions, "ai_remediation": ai_response.get("remediation", "")}))
            _complete_step(db, step5)

            session.status = "completed"
            session.completed_at = datetime.datetime.utcnow()
            db.commit()
            logger.info(f"Agent session {session_id} completed — no remediation needed.")

    except Exception as e:
        logger.error(f"Agent session {session_id} failed: {e}")
        try:
            session = db.query(models.AgentSession).filter(models.AgentSession.id == session_id).first()
            if session:
                session.status = "failed"
                session.completed_at = datetime.datetime.utcnow()
                current_step += 1
                _add_step(db, session_id, current_step, "error",
                         "Investigation Failed",
                         str(e),
                         status="failed",
                         result_data=json.dumps({"error": str(e)}))
                db.commit()
        except Exception:
            pass
    finally:
        db.close()


def execute_approved_actions(session_id: int, step_id: int):
    """Execute remediation actions after operator approval."""
    db = SessionLocal()
    try:
        step = db.query(models.AgentStep).filter(
            models.AgentStep.id == step_id,
            models.AgentStep.session_id == session_id
        ).first()

        if not step or step.status != "pending_approval":
            return

        step.status = "approved"
        step.completed_at = datetime.datetime.utcnow()
        db.commit()

        # Parse proposed actions
        result = json.loads(step.result_data) if step.result_data else {}
        actions = result.get("actions", [])

        session = db.query(models.AgentSession).filter(models.AgentSession.id == session_id).first()
        next_step_num = step.step_number + 1

        # Create execution log steps for each action
        for action in actions:
            if action["type"] == "informational":
                continue

            exec_step = _add_step(db, session_id, next_step_num, "execute",
                                f"Executing: {action['title']}",
                                f"Running: {action.get('command', 'N/A')}",
                                status="running")

            # Simulate action execution (in production, this would run real commands)
            _complete_step(db, exec_step, json.dumps({
                "action": action,
                "execution_result": "simulated",
                "message": f"Action '{action['title']}' has been logged. In production, this would execute: {action.get('command', 'N/A')}",
                "timestamp": datetime.datetime.utcnow().isoformat()
            }))
            next_step_num += 1

        # Final summary step
        summary_step = _add_step(db, session_id, next_step_num, "summary",
                                "Investigation Complete",
                                f"All approved remediation actions have been executed. Investigation of {session.target} is complete.")
        _complete_step(db, summary_step, json.dumps({
            "total_actions_executed": len([a for a in actions if a["type"] != "informational"]),
            "status": "all_actions_completed"
        }))

        session.status = "completed"
        session.completed_at = datetime.datetime.utcnow()
        db.commit()

    except Exception as e:
        logger.error(f"Failed to execute approved actions for session {session_id}: {e}")
    finally:
        db.close()

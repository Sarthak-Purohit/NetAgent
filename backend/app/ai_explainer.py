import os
import json
import logging
import httpx
from typing import Dict, Any
from .models import Scan, Alert

logger = logging.getLogger("netagent.ai_explainer")

# Environment configurations
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama2")
OLLAMA_TIMEOUT = float(os.getenv("OLLAMA_TIMEOUT", "10.0"))

def generate_scan_prompt(scan: Scan) -> str:
    ports_info = []
    for r in scan.results:
        vuln_str = f" (Vulnerabilities: {r.vulnerabilities})" if r.vulnerabilities else ""
        service_str = f", Service: {r.service}" if r.service else ""
        banner_str = f", Banner: {r.banner}" if r.banner else ""
        ports_info.append(f"- Port {r.port}/{r.protocol} ({r.state}{service_str}{banner_str}){vuln_str}")
    
    ports_text = "\n".join(ports_info) if ports_info else "No open ports found."
    return (
        f"Analyze the following network scan results for potential security threats.\n"
        f"Target: {scan.target}\n"
        f"Profile: {scan.profile}\n"
        f"Scan Results:\n{ports_text}\n\n"
        f"Provide an explanation of the scan results, evaluate the overall severity (must be one of: low, medium, high, critical), and list actionable remediation steps.\n\n"
        f"Respond ONLY with a JSON object containing these keys: \"explanation\", \"severity\", and \"remediation\"."
    )

def generate_alert_prompt(alert: Alert) -> str:
    return (
        f"Analyze the following security alert for network traffic anomaly.\n"
        f"Timestamp: {alert.timestamp}\n"
        f"Alert Type: {alert.alert_type}\n"
        f"Description: {alert.description}\n"
        f"Source IP: {alert.source_ip}\n"
        f"Destination IP: {alert.destination_ip}\n"
        f"Protocol: {alert.protocol}\n"
        f"Reported Severity: {alert.severity}\n\n"
        f"Provide a detailed explanation of this security threat, re-evaluate or confirm the severity (must be one of: low, medium, high, critical), and list actionable remediation steps.\n\n"
        f"Respond ONLY with a JSON object containing these keys: \"explanation\", \"severity\", and \"remediation\"."
    )

async def query_ollama(prompt: str) -> Dict[str, Any]:
    url = f"{OLLAMA_BASE_URL.rstrip('/')}/api/generate"
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "format": "json",
        "stream": False
    }
    
    async with httpx.AsyncClient(timeout=OLLAMA_TIMEOUT) as client:
        response = await client.post(url, json=payload)
        response.raise_for_status()
        res_json = response.json()
        raw_text = res_json.get("response", "")
        data = json.loads(raw_text)
        
        required_keys = {"explanation", "severity", "remediation"}
        if not required_keys.issubset(data.keys()):
            raise ValueError(f"Ollama response missing keys: {required_keys - data.keys()}")
            
        severity_lower = str(data["severity"]).lower()
        if severity_lower not in {"low", "medium", "high", "critical"}:
            severity_lower = "medium"
            
        return {
            "explanation": str(data["explanation"]),
            "severity": severity_lower,
            "remediation": str(data["remediation"])
        }

def get_mock_scan_explanation(scan: Scan) -> Dict[str, str]:
    # Extract vulnerabilities list
    vulnerabilities = []
    for r in scan.results:
        if r.vulnerabilities:
            # Split vulnerabilities by standard separator and trim whitespace
            parts = [v.strip() for v in r.vulnerabilities.split("|") if v.strip()]
            vulnerabilities.extend(parts)
            
    if vulnerabilities:
        explanation = (
            f"Active scan against {scan.target} using {scan.profile} profile discovered "
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
        ports_str = ", ".join([str(r.port) for r in scan.results])
        explanation = (
            f"Active scan against {scan.target} completed. Discovered open ports: {ports_str}. "
            "No signature-matching vulnerabilities were found in current repository definitions. "
            "However, leaving administrative ports open increases host attack surface."
        )
        severity = "low"
        remediation = (
            "1. Implement strict firewall access control lists (ACLs).\n"
            "2. Enforce strong multi-factor authentication (MFA) for services like SSH (22)."
        )
        
    return {
        "explanation": explanation,
        "severity": severity,
        "remediation": remediation
    }

def get_mock_alert_explanation(alert: Alert) -> Dict[str, str]:
    alert_type_lower = alert.alert_type.lower()
    description = alert.description
    
    if "ddos" in alert_type_lower:
        explanation = (
            f"The system detected a potential Distributed Denial of Service (DDoS) incident "
            f"({alert.alert_type}). Description: {description}. Multiple network endpoints are flooding "
            "the target with high packet volume, causing resource exhaustion and potential outage."
        )
        severity = "critical"
        remediation = (
            "1. Enable upstream rate-limiting policies at edge firewalls.\n"
            "2. Route traffic through a content delivery network (CDN) or dedicated DDoS mitigation provider.\n"
            "3. Configure connection timeouts to release resources more aggressively."
        )
    elif "port scan" in alert_type_lower:
        explanation = (
            f"Reconnaissance sweep detected: {alert.alert_type}. Description: {description}. "
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
            f"Security event triggered: {alert.alert_type}. Description: {description}. "
            "This behavior deviates from normal baseline traffic profiles and represents an intrusion risk."
        )
        severity = alert.severity.lower() if alert.severity else "medium"
        remediation = (
            "1. Review system and application logs on the target host.\n"
            "2. Verify host baseline file integrity.\n"
            "3. Perform deep inspection on packet payloads using Wireshark."
        )
        
    return {
        "explanation": explanation,
        "severity": severity,
        "remediation": remediation
    }

async def explain_scan(scan: Scan) -> Dict[str, str]:
    prompt = generate_scan_prompt(scan)
    try:
        return await query_ollama(prompt)
    except Exception as e:
        logger.warning(f"Ollama scan explanation failed: {e}. Falling back to mock explanation.")
        return get_mock_scan_explanation(scan)

async def explain_alert(alert: Alert) -> Dict[str, str]:
    prompt = generate_alert_prompt(alert)
    try:
        return await query_ollama(prompt)
    except Exception as e:
        logger.warning(f"Ollama alert explanation failed: {e}. Falling back to mock explanation.")
        return get_mock_alert_explanation(alert)

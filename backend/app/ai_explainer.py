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
OLLAMA_TIMEOUT = float(os.getenv("OLLAMA_TIMEOUT", "120.0"))

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

async def chat_with_ollama(message: str, history: list) -> str:
    url = f"{OLLAMA_BASE_URL.rstrip('/')}/api/chat"
    
    # 1. Start with system message matching user instructions
    messages = [
        {
            "role": "system",
            "content": "You are a cybersecurity auditor. Use tools to find security risks. Answer the user's questions about security, port scans, network alerts, and remediation steps."
        }
    ]
    
    # 2. Append history
    for msg in history:
        messages.append({
            "role": msg.role,
            "content": msg.content
        })
        
    # 3. Append current user message
    messages.append({
        "role": "user",
        "content": message
    })
    
    payload = {
        "model": OLLAMA_MODEL,
        "messages": messages,
        "stream": False
    }
    
    try:
        async with httpx.AsyncClient(timeout=OLLAMA_TIMEOUT) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
            res_json = response.json()
            message_obj = res_json.get("message", {})
            return message_obj.get("content", "No response returned from AI.")
    except Exception as e:
        logger.warning(f"Ollama chat query failed: {e}. Using rule-based fallback response.")
        return get_fallback_chat_response(message)

def get_fallback_chat_response(message: str) -> str:
    msg_lower = message.lower()
    
    if "auditor" in msg_lower or "instruction" in msg_lower or "rules" in msg_lower:
        return (
            "As a cybersecurity auditor, I have loaded the general instruction: **'You are a cybersecurity auditor. Use tools to find security risks'**.\n\n"
            "In this local offline fallback mode, I can analyze typical security risks. Tell me what ports or services you are concerned about (e.g., SSH, FTP, Database, RDP)."
        )
    if "ssh" in msg_lower:
        return (
            "### SSH Security Advisory (Port 22)\n\n"
            "SSH is commonly targeted for brute-force attacks.\n"
            "* **Remediation**:\n"
            "  1. Disable password authentication (`PasswordAuthentication no` in `/etc/ssh/sshd_config`) and enforce public-key authentication.\n"
            "  2. Change the default port from 22 to a random high port.\n"
            "  3. Use tools like `Fail2Ban` to block IPs with excessive authentication failures."
        )
    if "db" in msg_lower or "mysql" in msg_lower or "postgres" in msg_lower or "database" in msg_lower:
        return (
            "### Database Exposure Advisory (Port 3306/5432)\n\n"
            "Exposed database interfaces are high-risk targets.\n"
            "* **Remediation**:\n"
            "  1. Bind database services to `127.0.0.1` (localhost only) unless remote access is strictly required.\n"
            "  2. Restrict external firewall access to trusted IP ranges or enforce connection via a VPN.\n"
            "  3. Use strong, unique credentials and disable remote root access."
        )
    if "scan" in msg_lower or "scanner" in msg_lower:
        return (
            "### Scan Recommendations\n\n"
            "Network scanning helps identify exposed surface area.\n"
            "* **Best Practices**:\n"
            "  1. Run **Quick Scans** weekly to detect unexpected new open ports.\n"
            "  2. Run **Full Scans** monthly for a deeper dive into banners and version numbers.\n"
            "  3. Always audit scan results to ensure no plaintext protocols (FTP, Telnet) are exposed."
        )
    
    return (
        "🤖 **NetAgent AI Copilot (Offline Fallback Mode)**\n\n"
        "I am currently running in offline fallback mode because the local Ollama instance is disconnected.\n\n"
        "Here is what you can ask me:\n"
        "* How to secure **SSH** (port 22)?\n"
        "* What are the risks of exposed **databases**?\n"
        "* How does the NetAgent **Active Scanner** work?\n\n"
        "Please connect/start your local Ollama server to unlock full conversational AI reasoning."
    )


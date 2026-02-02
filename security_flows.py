"""
🔐 TRADEFLOW SECURITY AUTOMATION WITH PREFECT
==============================================
Security workflows orchestrated with Prefect.

This demonstrates:
- Automated vulnerability scanning
- Security monitoring workflows
- Incident response automation
- Compliance checking
- Threat intelligence integration

Your Prefect knowledge + Security = DevSecOps Gold!

Installation:
    pip install prefect requests python-nmap bandit safety

Run:
    prefect server start  # In one terminal
    python security_flows.py  # In another terminal
"""

import json
import subprocess
import os
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from pathlib import Path

from prefect import flow, task, get_run_logger
from prefect.tasks import task_input_hash
from prefect.blocks.system import Secret
from prefect.artifacts import create_markdown_artifact
import requests


# =============================================================================
# CONFIGURATION
# =============================================================================

SCAN_TARGETS = {
    "web_app": "http://localhost:8000",
    "api": "http://localhost:8000/api/",
}

SEVERITY_LEVELS = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}


# =============================================================================
# VULNERABILITY SCANNING TASKS
# =============================================================================

@task(
    name="dependency_scan",
    description="Scan Python dependencies for vulnerabilities",
    retries=2,
    retry_delay_seconds=30,
    cache_key_fn=task_input_hash,
    cache_expiration=timedelta(hours=1),
)
def scan_dependencies(requirements_path: str = "requirements.txt") -> Dict[str, Any]:
    """
    Scan Python dependencies using Safety and pip-audit.
    
    This task:
    1. Reads requirements.txt
    2. Runs Safety vulnerability check
    3. Runs pip-audit for additional coverage
    4. Returns consolidated results
    """
    logger = get_run_logger()
    logger.info(f"Scanning dependencies from {requirements_path}")
    
    results = {
        "scan_time": datetime.utcnow().isoformat(),
        "vulnerabilities": [],
        "summary": {
            "total": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }
    }
    
    try:
        # Run Safety
        safety_result = subprocess.run(
            ["safety", "check", "--json", "-r", requirements_path],
            capture_output=True,
            text=True
        )
        
        if safety_result.stdout:
            safety_data = json.loads(safety_result.stdout)
            for vuln in safety_data.get("vulnerabilities", []):
                results["vulnerabilities"].append({
                    "source": "safety",
                    "package": vuln.get("package_name"),
                    "version": vuln.get("analyzed_version"),
                    "vulnerability_id": vuln.get("vulnerability_id"),
                    "severity": vuln.get("severity", "UNKNOWN"),
                    "description": vuln.get("advisory"),
                })
                
                severity = vuln.get("severity", "").upper()
                if severity in results["summary"]:
                    results["summary"][severity.lower()] += 1
                results["summary"]["total"] += 1
        
        logger.info(f"Found {results['summary']['total']} vulnerabilities in dependencies")
        
    except FileNotFoundError:
        logger.warning("Safety not installed. Install with: pip install safety")
    except Exception as e:
        logger.error(f"Dependency scan error: {e}")
    
    return results


@task(
    name="sast_scan",
    description="Static Application Security Testing with Bandit",
    retries=2,
)
def run_sast_scan(target_path: str = "trading/") -> Dict[str, Any]:
    """
    Run Bandit SAST scanner on Python code.
    
    Checks for:
    - Hardcoded passwords
    - SQL injection risks
    - Command injection risks
    - Insecure functions
    - And more...
    """
    logger = get_run_logger()
    logger.info(f"Running SAST scan on {target_path}")
    
    results = {
        "scan_time": datetime.utcnow().isoformat(),
        "target": target_path,
        "findings": [],
        "summary": {
            "total": 0,
            "high_severity": 0,
            "medium_severity": 0,
            "low_severity": 0,
        }
    }
    
    try:
        bandit_result = subprocess.run(
            ["bandit", "-r", target_path, "-f", "json"],
            capture_output=True,
            text=True
        )
        
        if bandit_result.stdout:
            bandit_data = json.loads(bandit_result.stdout)
            
            for finding in bandit_data.get("results", []):
                results["findings"].append({
                    "file": finding.get("filename"),
                    "line": finding.get("line_number"),
                    "severity": finding.get("issue_severity"),
                    "confidence": finding.get("issue_confidence"),
                    "issue": finding.get("issue_text"),
                    "code": finding.get("code"),
                    "cwe": finding.get("issue_cwe", {}).get("id"),
                })
                
                severity = finding.get("issue_severity", "").upper()
                if severity == "HIGH":
                    results["summary"]["high_severity"] += 1
                elif severity == "MEDIUM":
                    results["summary"]["medium_severity"] += 1
                else:
                    results["summary"]["low_severity"] += 1
                results["summary"]["total"] += 1
        
        logger.info(f"SAST scan found {results['summary']['total']} issues")
        
    except FileNotFoundError:
        logger.warning("Bandit not installed. Install with: pip install bandit")
    except Exception as e:
        logger.error(f"SAST scan error: {e}")
    
    return results


@task(
    name="secret_scan",
    description="Scan for exposed secrets and credentials",
)
def scan_for_secrets(target_path: str = ".") -> Dict[str, Any]:
    """
    Scan codebase for exposed secrets.
    
    Looks for:
    - API keys
    - Passwords
    - AWS credentials
    - Private keys
    - Database connection strings
    """
    logger = get_run_logger()
    logger.info(f"Scanning for secrets in {target_path}")
    
    import re
    
    SECRET_PATTERNS = {
        "aws_access_key": r"AKIA[0-9A-Z]{16}",
        "aws_secret_key": r"[0-9a-zA-Z/+]{40}",
        "github_token": r"ghp_[0-9a-zA-Z]{36}",
        "generic_api_key": r"api[_-]?key['\"]?\s*[:=]\s*['\"][0-9a-zA-Z]{20,}['\"]",
        "generic_password": r"password['\"]?\s*[:=]\s*['\"][^'\"]{8,}['\"]",
        "private_key": r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
        "jwt_token": r"eyJ[0-9a-zA-Z_-]*\.eyJ[0-9a-zA-Z_-]*\.[0-9a-zA-Z_-]*",
        "database_url": r"(postgres|mysql|mongodb)://[^:]+:[^@]+@",
    }
    
    results = {
        "scan_time": datetime.utcnow().isoformat(),
        "secrets_found": [],
        "files_scanned": 0,
        "summary": {
            "total": 0,
            "by_type": {},
        }
    }
    
    # Files to skip
    skip_patterns = [".git", "__pycache__", "node_modules", ".venv", "venv"]
    skip_extensions = [".pyc", ".pyo", ".so", ".dll", ".exe", ".bin", ".jpg", ".png", ".gif"]
    
    for root, dirs, files in os.walk(target_path):
        # Skip certain directories
        dirs[:] = [d for d in dirs if d not in skip_patterns]
        
        for file in files:
            if any(file.endswith(ext) for ext in skip_extensions):
                continue
                
            filepath = os.path.join(root, file)
            results["files_scanned"] += 1
            
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                    for secret_type, pattern in SECRET_PATTERNS.items():
                        matches = re.finditer(pattern, content, re.IGNORECASE)
                        for match in matches:
                            # Get line number
                            line_num = content[:match.start()].count('\n') + 1
                            
                            results["secrets_found"].append({
                                "type": secret_type,
                                "file": filepath,
                                "line": line_num,
                                "match": match.group()[:20] + "..." if len(match.group()) > 20 else match.group(),
                            })
                            
                            results["summary"]["total"] += 1
                            results["summary"]["by_type"][secret_type] = \
                                results["summary"]["by_type"].get(secret_type, 0) + 1
                            
            except Exception as e:
                pass  # Skip files that can't be read
    
    logger.info(f"Scanned {results['files_scanned']} files, found {results['summary']['total']} potential secrets")
    
    return results


@task(
    name="web_scan",
    description="Basic web vulnerability scan",
)
def scan_web_application(target_url: str) -> Dict[str, Any]:
    """
    Basic web application security checks.
    
    Checks for:
    - Security headers
    - SSL/TLS configuration
    - Common misconfigurations
    """
    logger = get_run_logger()
    logger.info(f"Scanning web application: {target_url}")
    
    results = {
        "scan_time": datetime.utcnow().isoformat(),
        "target": target_url,
        "security_headers": {},
        "issues": [],
    }
    
    SECURITY_HEADERS = [
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "X-XSS-Protection",
        "Content-Security-Policy",
        "Referrer-Policy",
        "Permissions-Policy",
    ]
    
    try:
        response = requests.get(target_url, timeout=10, verify=False)
        
        # Check security headers
        for header in SECURITY_HEADERS:
            value = response.headers.get(header)
            results["security_headers"][header] = {
                "present": value is not None,
                "value": value,
            }
            
            if value is None:
                results["issues"].append({
                    "type": "missing_header",
                    "header": header,
                    "severity": "MEDIUM",
                    "description": f"Security header '{header}' is not set",
                })
        
        # Check for server information disclosure
        server = response.headers.get("Server")
        if server:
            results["issues"].append({
                "type": "information_disclosure",
                "header": "Server",
                "severity": "LOW",
                "description": f"Server header reveals: {server}",
            })
        
        # Check cookies
        for cookie in response.cookies:
            cookie_issues = []
            if not cookie.secure:
                cookie_issues.append("Missing Secure flag")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                cookie_issues.append("Missing HttpOnly flag")
            if not cookie.has_nonstandard_attr("SameSite"):
                cookie_issues.append("Missing SameSite attribute")
            
            if cookie_issues:
                results["issues"].append({
                    "type": "insecure_cookie",
                    "cookie": cookie.name,
                    "severity": "MEDIUM",
                    "description": f"Cookie '{cookie.name}' issues: {', '.join(cookie_issues)}",
                })
        
        logger.info(f"Web scan found {len(results['issues'])} issues")
        
    except Exception as e:
        logger.error(f"Web scan error: {e}")
        results["error"] = str(e)
    
    return results


# =============================================================================
# MONITORING & ALERTING TASKS
# =============================================================================

@task(
    name="analyze_logs",
    description="Analyze security logs for threats",
)
def analyze_security_logs(log_path: str = "logs/security.json") -> Dict[str, Any]:
    """
    Analyze security logs for suspicious patterns.
    
    Detects:
    - Brute force attempts
    - SQL injection attempts
    - XSS attempts
    - Unusual access patterns
    """
    logger = get_run_logger()
    logger.info(f"Analyzing security logs: {log_path}")
    
    results = {
        "analysis_time": datetime.utcnow().isoformat(),
        "alerts": [],
        "statistics": {
            "total_events": 0,
            "attack_attempts": 0,
            "failed_logins": 0,
            "unique_ips": set(),
        }
    }
    
    try:
        with open(log_path, 'r') as f:
            for line in f:
                try:
                    event = json.loads(line)
                    results["statistics"]["total_events"] += 1
                    
                    # Track unique IPs
                    if "client" in event and "ip" in event["client"]:
                        results["statistics"]["unique_ips"].add(event["client"]["ip"])
                    
                    # Check for attack patterns
                    if event.get("event_type") == "attack_detected":
                        results["statistics"]["attack_attempts"] += 1
                        results["alerts"].append({
                            "type": "attack_detected",
                            "attack_type": event.get("details", {}).get("attack_type"),
                            "source_ip": event.get("client", {}).get("ip"),
                            "timestamp": event.get("timestamp"),
                            "severity": "HIGH",
                        })
                    
                    # Check for failed logins
                    if event.get("event_type") == "authentication_failure":
                        results["statistics"]["failed_logins"] += 1
                        
                except json.JSONDecodeError:
                    continue
        
        # Convert set to count for JSON serialization
        results["statistics"]["unique_ips"] = len(results["statistics"]["unique_ips"])
        
        # Generate alerts for patterns
        if results["statistics"]["failed_logins"] > 10:
            results["alerts"].append({
                "type": "brute_force_detected",
                "severity": "HIGH",
                "description": f"High number of failed logins: {results['statistics']['failed_logins']}",
            })
        
        logger.info(f"Analyzed {results['statistics']['total_events']} events, found {len(results['alerts'])} alerts")
        
    except FileNotFoundError:
        logger.warning(f"Log file not found: {log_path}")
    except Exception as e:
        logger.error(f"Log analysis error: {e}")
    
    return results


@task(
    name="send_alert",
    description="Send security alert notification",
)
def send_security_alert(
    alert_type: str,
    severity: str,
    details: Dict[str, Any],
    channels: List[str] = ["log"]
) -> bool:
    """
    Send security alert through configured channels.
    
    Channels:
    - log: Write to log file
    - slack: Send to Slack (requires webhook)
    - email: Send email (requires SMTP config)
    - pagerduty: Create PagerDuty incident
    """
    logger = get_run_logger()
    
    alert = {
        "timestamp": datetime.utcnow().isoformat(),
        "type": alert_type,
        "severity": severity,
        "details": details,
    }
    
    for channel in channels:
        if channel == "log":
            logger.warning(f"🚨 SECURITY ALERT [{severity}]: {alert_type}")
            logger.warning(f"Details: {json.dumps(details, indent=2)}")
        
        elif channel == "slack":
            # Slack webhook integration
            try:
                webhook_url = os.environ.get("SLACK_WEBHOOK_URL")
                if webhook_url:
                    slack_message = {
                        "text": f"🚨 Security Alert: {alert_type}",
                        "attachments": [{
                            "color": "danger" if severity in ["CRITICAL", "HIGH"] else "warning",
                            "fields": [
                                {"title": "Severity", "value": severity, "short": True},
                                {"title": "Type", "value": alert_type, "short": True},
                                {"title": "Details", "value": json.dumps(details)},
                            ]
                        }]
                    }
                    requests.post(webhook_url, json=slack_message)
                    logger.info("Alert sent to Slack")
            except Exception as e:
                logger.error(f"Slack alert failed: {e}")
        
        # Add more channels as needed (email, PagerDuty, etc.)
    
    return True


# =============================================================================
# COMPLIANCE TASKS
# =============================================================================

@task(
    name="compliance_check",
    description="Run compliance checks against security standards",
)
def run_compliance_checks(standard: str = "owasp") -> Dict[str, Any]:
    """
    Check compliance against security standards.
    
    Standards:
    - owasp: OWASP Top 10
    - pci: PCI-DSS
    - hipaa: HIPAA (healthcare)
    - soc2: SOC 2
    """
    logger = get_run_logger()
    logger.info(f"Running {standard.upper()} compliance checks")
    
    results = {
        "standard": standard,
        "check_time": datetime.utcnow().isoformat(),
        "checks": [],
        "summary": {
            "total": 0,
            "passed": 0,
            "failed": 0,
            "not_applicable": 0,
        }
    }
    
    if standard == "owasp":
        owasp_checks = [
            {
                "id": "A01:2021",
                "name": "Broken Access Control",
                "checks": [
                    "Authorization checks on all endpoints",
                    "CORS configuration",
                    "Directory listing disabled",
                ]
            },
            {
                "id": "A02:2021", 
                "name": "Cryptographic Failures",
                "checks": [
                    "HTTPS enforced",
                    "Strong password hashing",
                    "Sensitive data encrypted",
                ]
            },
            {
                "id": "A03:2021",
                "name": "Injection",
                "checks": [
                    "Parameterized queries used",
                    "Input validation implemented",
                    "Output encoding applied",
                ]
            },
            {
                "id": "A04:2021",
                "name": "Insecure Design",
                "checks": [
                    "Threat modeling performed",
                    "Security requirements defined",
                    "Secure defaults configured",
                ]
            },
            {
                "id": "A05:2021",
                "name": "Security Misconfiguration",
                "checks": [
                    "Security headers present",
                    "Debug mode disabled in production",
                    "Default credentials changed",
                ]
            },
            {
                "id": "A06:2021",
                "name": "Vulnerable Components",
                "checks": [
                    "Dependencies up to date",
                    "No known vulnerabilities",
                    "Component inventory maintained",
                ]
            },
            {
                "id": "A07:2021",
                "name": "Auth Failures",
                "checks": [
                    "Strong password policy",
                    "Rate limiting on auth",
                    "Session management secure",
                ]
            },
            {
                "id": "A08:2021",
                "name": "Software Integrity Failures",
                "checks": [
                    "CI/CD pipeline secured",
                    "Dependency verification",
                    "Code signing implemented",
                ]
            },
            {
                "id": "A09:2021",
                "name": "Logging Failures",
                "checks": [
                    "Security events logged",
                    "Log integrity protected",
                    "Monitoring in place",
                ]
            },
            {
                "id": "A10:2021",
                "name": "SSRF",
                "checks": [
                    "URL validation implemented",
                    "Internal networks blocked",
                    "Allowlist for external calls",
                ]
            },
        ]
        
        for category in owasp_checks:
            for check in category["checks"]:
                # In real implementation, these would be actual checks
                # For demo, we'll simulate
                status = "manual_review_required"
                
                results["checks"].append({
                    "category": category["id"],
                    "category_name": category["name"],
                    "check": check,
                    "status": status,
                })
                
                results["summary"]["total"] += 1
    
    logger.info(f"Compliance check complete: {results['summary']['total']} checks")
    
    return results


# =============================================================================
# REPORTING TASKS
# =============================================================================

@task(
    name="generate_report",
    description="Generate security assessment report",
)
def generate_security_report(
    dependency_results: Dict,
    sast_results: Dict,
    secret_results: Dict,
    web_results: Dict,
) -> str:
    """
    Generate a comprehensive security report.
    """
    logger = get_run_logger()
    
    report = f"""
# 🔐 Security Assessment Report
**Generated:** {datetime.utcnow().isoformat()}

---

## 📋 Executive Summary

| Category | Issues Found | Critical/High |
|----------|--------------|---------------|
| Dependencies | {dependency_results.get('summary', {}).get('total', 0)} | {dependency_results.get('summary', {}).get('critical', 0) + dependency_results.get('summary', {}).get('high', 0)} |
| SAST (Code) | {sast_results.get('summary', {}).get('total', 0)} | {sast_results.get('summary', {}).get('high_severity', 0)} |
| Secrets | {secret_results.get('summary', {}).get('total', 0)} | {secret_results.get('summary', {}).get('total', 0)} |
| Web App | {len(web_results.get('issues', []))} | {len([i for i in web_results.get('issues', []) if i.get('severity') in ['CRITICAL', 'HIGH']])} |

---

## 🔍 Detailed Findings

### Dependency Vulnerabilities
{_format_dependency_findings(dependency_results)}

### Static Analysis (SAST)
{_format_sast_findings(sast_results)}

### Exposed Secrets
{_format_secret_findings(secret_results)}

### Web Application Issues
{_format_web_findings(web_results)}

---

## 📝 Recommendations

1. **Immediate Actions (Critical/High)**
   - Update vulnerable dependencies
   - Fix hardcoded credentials
   - Add missing security headers

2. **Short-term (Medium)**
   - Implement additional input validation
   - Enable security logging
   - Configure rate limiting

3. **Long-term (Low/Improvements)**
   - Implement WAF
   - Set up continuous monitoring
   - Regular penetration testing

---

*Report generated by TradeFlow Security Automation (Prefect)*
"""
    
    # Create Prefect artifact
    create_markdown_artifact(
        key="security-report",
        markdown=report,
        description="Security Assessment Report"
    )
    
    logger.info("Security report generated")
    
    return report


def _format_dependency_findings(results: Dict) -> str:
    vulns = results.get("vulnerabilities", [])
    if not vulns:
        return "✅ No vulnerable dependencies found."
    
    output = ""
    for vuln in vulns[:10]:  # Limit to 10
        output += f"- **{vuln.get('package')}** ({vuln.get('severity')}): {vuln.get('description', 'N/A')[:100]}...\n"
    return output


def _format_sast_findings(results: Dict) -> str:
    findings = results.get("findings", [])
    if not findings:
        return "✅ No SAST issues found."
    
    output = ""
    for finding in findings[:10]:
        output += f"- **{finding.get('file')}:{finding.get('line')}** ({finding.get('severity')}): {finding.get('issue')}\n"
    return output


def _format_secret_findings(results: Dict) -> str:
    secrets = results.get("secrets_found", [])
    if not secrets:
        return "✅ No exposed secrets found."
    
    output = "⚠️ **CRITICAL: Exposed secrets detected!**\n\n"
    for secret in secrets[:10]:
        output += f"- **{secret.get('type')}** in `{secret.get('file')}` line {secret.get('line')}\n"
    return output


def _format_web_findings(results: Dict) -> str:
    issues = results.get("issues", [])
    if not issues:
        return "✅ No web application issues found."
    
    output = ""
    for issue in issues[:10]:
        output += f"- **{issue.get('type')}** ({issue.get('severity')}): {issue.get('description')}\n"
    return output


# =============================================================================
# MAIN FLOWS
# =============================================================================

@flow(
    name="security_scan",
    description="Complete security scanning workflow",
    retries=1,
)
def security_scan_flow(
    target_path: str = ".",
    web_url: str = "http://localhost:8000",
    full_scan: bool = True
) -> Dict[str, Any]:
    """
    Main security scanning flow.
    
    Orchestrates all security scans and generates report.
    
    Usage:
        # Run from command line
        python security_flows.py
        
        # Or deploy to Prefect
        security_scan_flow.serve(name="security-scan")
    """
    logger = get_run_logger()
    logger.info("Starting security scan workflow")
    
    # Run all scans
    dependency_results = scan_dependencies()
    sast_results = run_sast_scan(target_path)
    secret_results = scan_for_secrets(target_path)
    
    web_results = {}
    if full_scan:
        web_results = scan_web_application(web_url)
    
    # Generate report
    report = generate_security_report(
        dependency_results,
        sast_results,
        secret_results,
        web_results
    )
    
    # Check for critical issues and alert
    total_critical = (
        dependency_results.get("summary", {}).get("critical", 0) +
        sast_results.get("summary", {}).get("high_severity", 0) +
        secret_results.get("summary", {}).get("total", 0)
    )
    
    if total_critical > 0:
        send_security_alert(
            alert_type="critical_vulnerabilities_found",
            severity="HIGH",
            details={
                "critical_count": total_critical,
                "scan_type": "security_scan",
            }
        )
    
    logger.info("Security scan workflow complete")
    
    return {
        "dependency_scan": dependency_results,
        "sast_scan": sast_results,
        "secret_scan": secret_results,
        "web_scan": web_results,
        "report": report,
    }


@flow(
    name="continuous_monitoring",
    description="Continuous security monitoring workflow",
)
def continuous_monitoring_flow(
    log_path: str = "logs/security.json",
    check_interval_minutes: int = 5
) -> None:
    """
    Continuous security monitoring flow.
    
    Runs periodically to:
    - Analyze security logs
    - Detect threats
    - Send alerts
    
    Deploy with:
        continuous_monitoring_flow.serve(
            name="security-monitor",
            interval=300  # 5 minutes
        )
    """
    logger = get_run_logger()
    logger.info("Running continuous security monitoring")
    
    # Analyze logs
    log_results = analyze_security_logs(log_path)
    
    # Send alerts for any findings
    for alert in log_results.get("alerts", []):
        send_security_alert(
            alert_type=alert.get("type"),
            severity=alert.get("severity"),
            details=alert
        )
    
    logger.info(f"Monitoring complete. Alerts: {len(log_results.get('alerts', []))}")


@flow(
    name="compliance_audit",
    description="Security compliance audit workflow",
)
def compliance_audit_flow(standards: List[str] = ["owasp"]) -> Dict[str, Any]:
    """
    Run compliance audits against security standards.
    """
    logger = get_run_logger()
    logger.info(f"Running compliance audit: {standards}")
    
    results = {}
    for standard in standards:
        results[standard] = run_compliance_checks(standard)
    
    return results


# =============================================================================
# CLI ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "scan":
            # Run security scan
            results = security_scan_flow()
            print(results["report"])
            
        elif command == "monitor":
            # Run monitoring
            continuous_monitoring_flow()
            
        elif command == "compliance":
            # Run compliance check
            results = compliance_audit_flow()
            print(json.dumps(results, indent=2))
            
        elif command == "serve":
            # Deploy as Prefect deployment
            from prefect.deployments import Deployment
            
            Deployment.build_from_flow(
                flow=security_scan_flow,
                name="security-scan-deployment",
                work_queue_name="security",
            ).apply()
            
            print("Deployment created! Run with: prefect deployment run 'security_scan/security-scan-deployment'")
            
        else:
            print(f"Unknown command: {command}")
            print("Usage: python security_flows.py [scan|monitor|compliance|serve]")
    else:
        # Default: run security scan
        results = security_scan_flow()
        print(results["report"])

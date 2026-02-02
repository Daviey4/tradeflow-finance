"""
🟣 SECURITY MONITORING & SIEM INTEGRATION
==========================================
Blue Team detection and monitoring system for TradeFlow.

This module provides:
- Security event logging
- Attack detection rules
- SIEM-ready log format
- Alert generation
- Incident tracking

Use this to practice:
- Log analysis
- Threat hunting
- Detection engineering
- Incident response
"""

import json
import re
import hashlib
import logging
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict
from django.http import JsonResponse
from django.core.cache import cache
from django.conf import settings

# =============================================================================
# SECURITY LOGGER CONFIGURATION
# =============================================================================

class SecurityLogger:
    """
    SIEM-ready security event logger.
    Outputs JSON logs compatible with Splunk, ELK, Azure Sentinel, etc.
    """
    
    def __init__(self):
        self.logger = logging.getLogger('security')
        handler = logging.FileHandler('logs/security.json')
        handler.setFormatter(logging.Formatter('%(message)s'))
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
    
    def log_event(self, event_type: str, severity: str, details: dict, request=None):
        """Log a security event in SIEM-compatible format"""
        
        event = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'event_type': event_type,
            'severity': severity,  # LOW, MEDIUM, HIGH, CRITICAL
            'details': details,
            'source': 'tradeflow',
        }
        
        if request:
            event['client'] = {
                'ip': self._get_client_ip(request),
                'user_agent': request.META.get('HTTP_USER_AGENT', ''),
                'session_id': request.session.session_key,
                'method': request.method,
                'path': request.path,
                'query_string': request.META.get('QUERY_STRING', ''),
            }
            
            # Add user info if authenticated
            if hasattr(request, 'user') and request.user.is_authenticated:
                event['user'] = {
                    'id': request.user.id,
                    'username': request.user.username,
                }
        
        self.logger.info(json.dumps(event))
        return event
    
    def _get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', 'unknown')


# Global logger instance
security_logger = SecurityLogger()


# =============================================================================
# ATTACK DETECTION RULES
# =============================================================================

class AttackDetector:
    """
    Detection rules for common attacks.
    Each rule returns (detected: bool, attack_type: str, confidence: float)
    """
    
    # SQL Injection patterns
    SQLI_PATTERNS = [
        r"('|\")\s*(or|and)\s*('|\")?[0-9]",  # ' or '1'='1
        r"('|\")\s*(or|and)\s+.*=",            # ' or 1=1
        r"union\s+(all\s+)?select",            # UNION SELECT
        r";\s*(drop|delete|update|insert)",    # ; DROP TABLE
        r"('|\")\s*;\s*--",                    # '; --
        r"sleep\s*\(\s*\d+\s*\)",              # SLEEP(5)
        r"benchmark\s*\(",                      # BENCHMARK()
        r"waitfor\s+delay",                     # WAITFOR DELAY
        r"(\'|\")\s*\|\|",                     # String concatenation
        r"extractvalue\s*\(",                   # XML extraction
    ]
    
    # XSS patterns
    XSS_PATTERNS = [
        r"<script[^>]*>",                      # <script>
        r"javascript\s*:",                      # javascript:
        r"on\w+\s*=",                          # onclick=, onerror=
        r"<img[^>]+onerror",                   # <img onerror=
        r"<svg[^>]+onload",                    # <svg onload=
        r"expression\s*\(",                    # CSS expression()
        r"<iframe",                             # iframe injection
        r"document\.(cookie|location|write)",  # DOM manipulation
        r"alert\s*\(",                         # alert()
        r"eval\s*\(",                          # eval()
    ]
    
    # Command Injection patterns
    CMDI_PATTERNS = [
        r";\s*\w+",                            # ; command
        r"\|\s*\w+",                           # | command
        r"\$\([^)]+\)",                        # $(command)
        r"`[^`]+`",                            # `command`
        r"&&\s*\w+",                           # && command
        r"\|\|\s*\w+",                         # || command
        r">\s*/",                              # > /path
        r"<\s*/",                              # < /path
    ]
    
    # Path Traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",                              # ../
        r"\.\.\\",                             # ..\
        r"%2e%2e[%2f\\]",                      # URL encoded ../
        r"/etc/passwd",                        # Direct file access
        r"/etc/shadow",
        r"c:\\windows",
        r"/proc/self",
    ]
    
    # SSRF patterns
    SSRF_PATTERNS = [
        r"169\.254\.169\.254",                 # AWS metadata
        r"localhost",
        r"127\.0\.0\.1",
        r"0\.0\.0\.0",
        r"10\.\d+\.\d+\.\d+",                 # Private IP
        r"172\.(1[6-9]|2\d|3[01])\.",         # Private IP
        r"192\.168\.",                         # Private IP
        r"file://",                            # File protocol
        r"gopher://",                          # Gopher protocol
    ]
    
    @classmethod
    def detect_sqli(cls, value: str) -> tuple:
        """Detect SQL injection attempts"""
        value_lower = value.lower()
        for pattern in cls.SQLI_PATTERNS:
            if re.search(pattern, value_lower):
                return (True, 'sql_injection', 0.9)
        return (False, None, 0)
    
    @classmethod
    def detect_xss(cls, value: str) -> tuple:
        """Detect XSS attempts"""
        value_lower = value.lower()
        for pattern in cls.XSS_PATTERNS:
            if re.search(pattern, value_lower):
                return (True, 'xss', 0.85)
        return (False, None, 0)
    
    @classmethod
    def detect_cmdi(cls, value: str) -> tuple:
        """Detect command injection attempts"""
        for pattern in cls.CMDI_PATTERNS:
            if re.search(pattern, value):
                return (True, 'command_injection', 0.8)
        return (False, None, 0)
    
    @classmethod
    def detect_path_traversal(cls, value: str) -> tuple:
        """Detect path traversal attempts"""
        value_lower = value.lower()
        for pattern in cls.PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, value_lower):
                return (True, 'path_traversal', 0.9)
        return (False, None, 0)
    
    @classmethod
    def detect_ssrf(cls, value: str) -> tuple:
        """Detect SSRF attempts"""
        value_lower = value.lower()
        for pattern in cls.SSRF_PATTERNS:
            if re.search(pattern, value_lower):
                return (True, 'ssrf', 0.85)
        return (False, None, 0)
    
    @classmethod
    def analyze_request(cls, request) -> list:
        """
        Analyze entire request for attack patterns.
        Returns list of detected attacks.
        """
        detections = []
        
        # Check all input sources
        inputs_to_check = []
        
        # GET parameters
        for key, value in request.GET.items():
            inputs_to_check.append(('GET', key, value))
        
        # POST parameters
        for key, value in request.POST.items():
            inputs_to_check.append(('POST', key, value))
        
        # Path
        inputs_to_check.append(('PATH', 'path', request.path))
        
        # Headers of interest
        for header in ['HTTP_USER_AGENT', 'HTTP_REFERER', 'HTTP_COOKIE']:
            if header in request.META:
                inputs_to_check.append(('HEADER', header, request.META[header]))
        
        # Run all detectors
        for source, param, value in inputs_to_check:
            if not isinstance(value, str):
                continue
                
            for detector in [cls.detect_sqli, cls.detect_xss, cls.detect_cmdi, 
                           cls.detect_path_traversal, cls.detect_ssrf]:
                detected, attack_type, confidence = detector(value)
                if detected:
                    detections.append({
                        'attack_type': attack_type,
                        'confidence': confidence,
                        'source': source,
                        'parameter': param,
                        'value': value[:200],  # Truncate for logging
                    })
        
        return detections


# =============================================================================
# RATE LIMITING & BRUTE FORCE DETECTION
# =============================================================================

class BruteForceDetector:
    """Detect brute force and credential stuffing attacks"""
    
    # Thresholds
    FAILED_LOGIN_THRESHOLD = 5  # failures before alert
    FAILED_LOGIN_WINDOW = 300   # seconds (5 minutes)
    LOCKOUT_DURATION = 900      # seconds (15 minutes)
    
    @classmethod
    def record_failed_login(cls, ip: str, username: str) -> dict:
        """Record a failed login attempt"""
        
        # Track by IP
        ip_key = f"failed_login:ip:{ip}"
        ip_failures = cache.get(ip_key, [])
        ip_failures.append({
            'time': datetime.utcnow().isoformat(),
            'username': username,
        })
        
        # Keep only recent failures
        cutoff = datetime.utcnow() - timedelta(seconds=cls.FAILED_LOGIN_WINDOW)
        ip_failures = [f for f in ip_failures 
                       if datetime.fromisoformat(f['time']) > cutoff]
        
        cache.set(ip_key, ip_failures, cls.FAILED_LOGIN_WINDOW)
        
        # Track by username
        user_key = f"failed_login:user:{username}"
        user_failures = cache.get(user_key, 0) + 1
        cache.set(user_key, user_failures, cls.FAILED_LOGIN_WINDOW)
        
        # Check thresholds
        result = {
            'ip_failures': len(ip_failures),
            'user_failures': user_failures,
            'alert': False,
            'lockout': False,
        }
        
        if len(ip_failures) >= cls.FAILED_LOGIN_THRESHOLD:
            result['alert'] = True
            result['alert_type'] = 'brute_force_ip'
            
        if user_failures >= cls.FAILED_LOGIN_THRESHOLD:
            result['alert'] = True
            result['alert_type'] = 'brute_force_user'
            
        if len(ip_failures) >= cls.FAILED_LOGIN_THRESHOLD * 2:
            result['lockout'] = True
            cache.set(f"lockout:ip:{ip}", True, cls.LOCKOUT_DURATION)
        
        return result
    
    @classmethod
    def is_locked_out(cls, ip: str) -> bool:
        """Check if IP is locked out"""
        return cache.get(f"lockout:ip:{ip}", False)
    
    @classmethod
    def record_successful_login(cls, ip: str, username: str):
        """Clear failure counts on successful login"""
        cache.delete(f"failed_login:ip:{ip}")
        cache.delete(f"failed_login:user:{username}")


# =============================================================================
# SECURITY MIDDLEWARE
# =============================================================================

class SecurityMonitoringMiddleware:
    """
    Django middleware for security monitoring.
    Add to MIDDLEWARE in settings.py
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # Pre-request analysis
        self.analyze_request(request)
        
        # Process request
        response = self.get_response(request)
        
        # Post-request logging
        self.log_request(request, response)
        
        return response
    
    def analyze_request(self, request):
        """Analyze request for attacks before processing"""
        
        # Check for lockout
        ip = self._get_client_ip(request)
        if BruteForceDetector.is_locked_out(ip):
            security_logger.log_event(
                event_type='blocked_request',
                severity='HIGH',
                details={'reason': 'ip_lockout'},
                request=request
            )
        
        # Run attack detection
        detections = AttackDetector.analyze_request(request)
        
        for detection in detections:
            security_logger.log_event(
                event_type='attack_detected',
                severity='HIGH',
                details=detection,
                request=request
            )
    
    def log_request(self, request, response):
        """Log request after processing"""
        
        # Log authentication events
        if '/login' in request.path and request.method == 'POST':
            if response.status_code == 200:
                security_logger.log_event(
                    event_type='authentication_success',
                    severity='LOW',
                    details={'path': request.path},
                    request=request
                )
            elif response.status_code in [401, 403]:
                security_logger.log_event(
                    event_type='authentication_failure',
                    severity='MEDIUM',
                    details={
                        'path': request.path,
                        'status_code': response.status_code,
                    },
                    request=request
                )
        
        # Log sensitive endpoint access
        sensitive_paths = ['/admin', '/api/users', '/debug', '/vuln']
        for path in sensitive_paths:
            if request.path.startswith(path):
                security_logger.log_event(
                    event_type='sensitive_access',
                    severity='MEDIUM',
                    details={
                        'path': request.path,
                        'status_code': response.status_code,
                    },
                    request=request
                )
                break
        
        # Log errors that might indicate attacks
        if response.status_code >= 500:
            security_logger.log_event(
                event_type='server_error',
                severity='MEDIUM',
                details={
                    'path': request.path,
                    'status_code': response.status_code,
                },
                request=request
            )
    
    def _get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', 'unknown')


# =============================================================================
# DETECTION RULES FOR SIEM
# =============================================================================

SIEM_DETECTION_RULES = """
# =============================================================================
# SPLUNK DETECTION RULES
# =============================================================================
# Copy these into Splunk for alerting

# Rule 1: SQL Injection Attempts
index=tradeflow event_type="attack_detected" details.attack_type="sql_injection"
| stats count by client.ip, details.parameter
| where count > 3

# Rule 2: Brute Force Login
index=tradeflow event_type="authentication_failure"
| stats count by client.ip
| where count > 5
| table client.ip, count

# Rule 3: XSS Attempts
index=tradeflow event_type="attack_detected" details.attack_type="xss"
| stats count by client.ip
| where count > 2

# Rule 4: SSRF Attempts
index=tradeflow event_type="attack_detected" details.attack_type="ssrf"
| stats count by client.ip, details.value

# Rule 5: Unusual Admin Access
index=tradeflow event_type="sensitive_access" details.path="/admin*"
| stats count by client.ip, client.user_agent
| where count > 10

# Rule 6: Multiple Server Errors (possible fuzzing)
index=tradeflow event_type="server_error"
| bucket _time span=5m
| stats count by _time, client.ip
| where count > 20


# =============================================================================
# ELK/OPENSEARCH DETECTION RULES
# =============================================================================
# Use in Kibana Security -> Detection Rules

# Rule 1: SQL Injection
{
  "rule": {
    "name": "SQL Injection Attempt",
    "query": "event_type:attack_detected AND details.attack_type:sql_injection",
    "severity": "high",
    "threshold": {"value": 3, "field": "client.ip"}
  }
}

# Rule 2: Brute Force
{
  "rule": {
    "name": "Brute Force Login",
    "query": "event_type:authentication_failure",
    "severity": "medium",
    "threshold": {"value": 5, "field": "client.ip", "window": "5m"}
  }
}


# =============================================================================
# SIGMA RULES (Universal Format)
# =============================================================================
# Can be converted to any SIEM

title: SQL Injection Attempt Detected
status: production
description: Detects SQL injection attempts in web requests
logsource:
    product: tradeflow
    service: security
detection:
    selection:
        event_type: 'attack_detected'
        details.attack_type: 'sql_injection'
    condition: selection
level: high
tags:
    - attack.initial_access
    - attack.t1190

---

title: Brute Force Authentication
status: production
description: Detects brute force login attempts
logsource:
    product: tradeflow
    service: security
detection:
    selection:
        event_type: 'authentication_failure'
    condition: selection | count() by client.ip > 5
    timeframe: 5m
level: medium
tags:
    - attack.credential_access
    - attack.t1110

---

title: Cross-Site Scripting Attempt
status: production
description: Detects XSS attempts in user input
logsource:
    product: tradeflow
    service: security
detection:
    selection:
        event_type: 'attack_detected'
        details.attack_type: 'xss'
    condition: selection
level: high
tags:
    - attack.initial_access
    - attack.t1059
"""


# =============================================================================
# SECURITY DASHBOARD DATA API
# =============================================================================

def security_dashboard_data(request):
    """
    API endpoint for security dashboard.
    Returns metrics for visualization.
    """
    
    # In production, this would query your log aggregator
    # For demo, return sample structure
    
    data = {
        'summary': {
            'total_events_24h': 1250,
            'attacks_detected': 23,
            'blocked_ips': 5,
            'failed_logins': 45,
        },
        'attacks_by_type': [
            {'type': 'sql_injection', 'count': 12},
            {'type': 'xss', 'count': 7},
            {'type': 'brute_force', 'count': 15},
            {'type': 'ssrf', 'count': 3},
            {'type': 'path_traversal', 'count': 2},
        ],
        'attacks_by_hour': [
            # Last 24 hours
            {'hour': '00:00', 'count': 3},
            {'hour': '01:00', 'count': 1},
            # ... etc
        ],
        'top_attacking_ips': [
            {'ip': '192.168.1.100', 'count': 45, 'blocked': True},
            {'ip': '10.0.0.50', 'count': 23, 'blocked': False},
        ],
        'recent_alerts': [
            {
                'time': '2024-01-15T10:23:45Z',
                'type': 'sql_injection',
                'severity': 'HIGH',
                'source_ip': '192.168.1.100',
                'target': '/vuln/search/',
            },
        ],
    }
    
    return JsonResponse(data)


# =============================================================================
# INCIDENT RESPONSE PLAYBOOKS
# =============================================================================

INCIDENT_PLAYBOOKS = {
    'sql_injection': {
        'name': 'SQL Injection Response',
        'severity': 'HIGH',
        'steps': [
            '1. Immediately block source IP',
            '2. Review affected endpoints and queries',
            '3. Check for data exfiltration in logs',
            '4. Audit database for unauthorized changes',
            '5. Review and patch vulnerable code',
            '6. Implement WAF rules',
            '7. Document incident and notify stakeholders',
        ],
        'automated_actions': [
            'Block IP for 24 hours',
            'Generate alert to security team',
            'Capture full request for analysis',
        ],
    },
    'brute_force': {
        'name': 'Brute Force Response',
        'severity': 'MEDIUM',
        'steps': [
            '1. Verify if attack is ongoing',
            '2. Check if any accounts were compromised',
            '3. Force password reset for targeted accounts',
            '4. Implement progressive delays',
            '5. Consider CAPTCHA for affected endpoints',
            '6. Review rate limiting configuration',
        ],
        'automated_actions': [
            'Temporary IP block (15 min)',
            'Account lockout after 5 failures',
            'Alert security team if distributed',
        ],
    },
    'xss': {
        'name': 'XSS Attack Response',
        'severity': 'HIGH',
        'steps': [
            '1. Identify injection point',
            '2. Check if payload was stored',
            '3. Review user sessions for compromise',
            '4. Clear any stored malicious content',
            '5. Implement output encoding',
            '6. Add/strengthen CSP headers',
            '7. Review all similar input points',
        ],
        'automated_actions': [
            'Log full payload for analysis',
            'Alert security team',
            'Block IP if repeated attempts',
        ],
    },
}


# =============================================================================
# USAGE INSTRUCTIONS
# =============================================================================

"""
HOW TO USE THIS MODULE:

1. ADD MIDDLEWARE TO SETTINGS:
   
   MIDDLEWARE = [
       ...
       'trading.security_monitoring.SecurityMonitoringMiddleware',
   ]

2. CREATE LOGS DIRECTORY:
   
   mkdir -p logs
   touch logs/security.json

3. VIEW LOGS:
   
   tail -f logs/security.json | jq .

4. SEND TO SIEM:
   
   # Splunk Universal Forwarder
   [monitor://path/to/logs/security.json]
   sourcetype = _json
   index = tradeflow
   
   # Filebeat (ELK)
   filebeat.inputs:
   - type: log
     paths:
       - /path/to/logs/security.json
     json.keys_under_root: true

5. IMPORT DETECTION RULES:
   
   Copy rules from SIEM_DETECTION_RULES to your SIEM platform.

6. TEST DETECTION:
   
   # SQL Injection
   curl "http://localhost:8000/vuln/search/?q=' OR '1'='1"
   
   # XSS
   curl "http://localhost:8000/vuln/comment/?message=<script>alert(1)</script>"
   
   # Check logs
   tail logs/security.json | jq .
"""

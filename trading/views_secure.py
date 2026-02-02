"""
🔵 SECURE/HARDENED VIEWS - BLUE TEAM DEFENSIVE VERSION
=======================================================
This code demonstrates proper security controls to prevent
the vulnerabilities in the vulnerable version.

Security controls implemented:
- Parameterized queries (SQLi prevention)
- Output encoding (XSS prevention)
- CSRF tokens
- Proper authentication & authorization
- Input validation
- Secure password hashing
- Rate limiting
- Security headers
"""

import json
import re
import secrets
import logging
from functools import wraps
from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponseForbidden
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_http_methods
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password, check_password
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.utils.html import escape
from django.db import connection
from django.core.cache import cache
from django.conf import settings

# Set up security logging
security_logger = logging.getLogger('security')


# ============================================================
# SECURITY MIDDLEWARE & DECORATORS
# ============================================================

def rate_limit(key_prefix, limit=10, period=60):
    """
    🔵 SECURE: Rate limiting decorator
    Prevents brute force attacks
    """
    def decorator(func):
        @wraps(func)
        def wrapper(request, *args, **kwargs):
            # Create unique key based on IP
            ip = get_client_ip(request)
            cache_key = f"ratelimit:{key_prefix}:{ip}"
            
            # Check current count
            count = cache.get(cache_key, 0)
            
            if count >= limit:
                security_logger.warning(f"Rate limit exceeded for {ip} on {key_prefix}")
                return JsonResponse({
                    'error': 'Too many requests. Please try again later.'
                }, status=429)
            
            # Increment counter
            cache.set(cache_key, count + 1, period)
            
            return func(request, *args, **kwargs)
        return wrapper
    return decorator


def get_client_ip(request):
    """🔵 SECURE: Get real client IP, handling proxies"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def add_security_headers(response):
    """🔵 SECURE: Add security headers to response"""
    response['X-Content-Type-Options'] = 'nosniff'
    response['X-Frame-Options'] = 'DENY'
    response['X-XSS-Protection'] = '1; mode=block'
    response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
    response['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response


def ownership_required(model_class, id_param='pk'):
    """
    🔵 SECURE: Verify resource ownership
    Prevents IDOR attacks
    """
    def decorator(func):
        @wraps(func)
        def wrapper(request, *args, **kwargs):
            resource_id = kwargs.get(id_param)
            
            try:
                resource = model_class.objects.get(pk=resource_id)
                
                # Check ownership
                if hasattr(resource, 'portfolio'):
                    portfolio = resource.portfolio
                elif hasattr(resource, 'user'):
                    if resource.user != request.user:
                        security_logger.warning(
                            f"IDOR attempt: User {request.user.id} tried to access "
                            f"{model_class.__name__} {resource_id}"
                        )
                        return HttpResponseForbidden("Access denied")
                
                # Check session-based ownership
                session_id = request.session.session_key
                if hasattr(resource, 'session_id') and resource.session_id != session_id:
                    if not (hasattr(resource, 'portfolio') and resource.portfolio.session_id == session_id):
                        security_logger.warning(f"IDOR attempt from session {session_id}")
                        return HttpResponseForbidden("Access denied")
                
            except model_class.DoesNotExist:
                return JsonResponse({'error': 'Not found'}, status=404)
            
            return func(request, *args, **kwargs)
        return wrapper
    return decorator


# ============================================================
# SECURE: SQL INJECTION PREVENTION
# ============================================================

@csrf_protect
@require_http_methods(["GET", "POST"])
@rate_limit('login', limit=5, period=300)  # 5 attempts per 5 minutes
def secure_login(request):
    """
    🔵 SECURE: Login with parameterized queries
    
    Security controls:
    - Parameterized queries (no SQL injection)
    - Rate limiting (brute force prevention)
    - CSRF protection
    - Secure password comparison
    - Security logging
    """
    if request.method == 'POST':
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')
        
        # 🔵 SECURE: Input validation
        if not username or not password:
            return render(request, 'secure/login.html', {'error': 'All fields required'})
        
        if len(username) > 150 or len(password) > 128:
            return render(request, 'secure/login.html', {'error': 'Invalid input'})
        
        # 🔵 SECURE: Parameterized query - values passed separately
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT id, password FROM auth_user WHERE username = %s",
                [username]  # 🔵 Parameters passed as list, not concatenated
            )
            user = cursor.fetchone()
        
        if user:
            user_id, stored_password = user
            # 🔵 SECURE: Constant-time password comparison
            if check_password(password, stored_password):
                request.session['user_id'] = user_id
                request.session['username'] = username
                request.session.cycle_key()  # 🔵 SECURE: Session fixation prevention
                
                security_logger.info(f"Successful login for user {username}")
                return redirect('/dashboard/')
        
        # 🔵 SECURE: Generic error message (doesn't reveal if user exists)
        security_logger.warning(f"Failed login attempt for username: {username}")
        return render(request, 'secure/login.html', {'error': 'Invalid credentials'})
    
    return render(request, 'secure/login.html')


@csrf_protect
@require_http_methods(["GET"])
def secure_search(request):
    """
    🔵 SECURE: Search with parameterized queries
    """
    query = request.GET.get('q', '')
    
    # 🔵 SECURE: Input validation
    if len(query) > 100:
        return JsonResponse({'error': 'Query too long'}, status=400)
    
    # 🔵 SECURE: Sanitize - remove special characters
    query = re.sub(r'[^\w\s-]', '', query)
    
    # 🔵 SECURE: Parameterized query
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT id, trade_type, symbol, amount, price, created_at 
            FROM trading_trade 
            WHERE symbol LIKE %s OR reason LIKE %s
            LIMIT 50
            """,
            [f'%{query}%', f'%{query}%']  # 🔵 Parameters bound safely
        )
        columns = [col[0] for col in cursor.description]
        results = [dict(zip(columns, row)) for row in cursor.fetchall()]
    
    return JsonResponse({'results': results, 'query': escape(query)})


# ============================================================
# SECURE: XSS PREVENTION
# ============================================================

@csrf_protect
@require_http_methods(["GET", "POST"])
def secure_profile(request):
    """
    🔵 SECURE: Profile with XSS prevention
    
    Security controls:
    - HTML escaping all user input
    - Content-Security-Policy header
    - Input validation and sanitization
    """
    if request.method == 'POST':
        name = request.POST.get('name', '')
        bio = request.POST.get('bio', '')
        
        # 🔵 SECURE: Input validation
        if len(name) > 100 or len(bio) > 500:
            return render(request, 'secure/profile.html', {'error': 'Input too long'})
        
        # 🔵 SECURE: Strip HTML tags and escape
        name = escape(re.sub(r'<[^>]+>', '', name))
        bio = escape(re.sub(r'<[^>]+>', '', bio))
        
        request.session['profile_name'] = name
        request.session['profile_bio'] = bio
    
    context = {
        'name': escape(request.session.get('profile_name', 'Anonymous')),
        'bio': escape(request.session.get('profile_bio', 'No bio')),
    }
    
    response = render(request, 'secure/profile.html', context)
    return add_security_headers(response)


@require_http_methods(["GET"])
def secure_comment(request):
    """
    🔵 SECURE: Comment display with XSS prevention
    """
    message = request.GET.get('message', '')
    
    # 🔵 SECURE: Escape HTML entities
    safe_message = escape(message)
    
    response = render(request, 'secure/comment.html', {'message': safe_message})
    return add_security_headers(response)


# ============================================================
# SECURE: IDOR PREVENTION
# ============================================================

@csrf_protect
@require_http_methods(["GET"])
def secure_portfolio(request, user_id):
    """
    🔵 SECURE: Portfolio access with authorization check
    """
    from .models import Portfolio, Trade, Holding
    
    # 🔵 SECURE: Get current user's session
    session_id = request.session.session_key
    if not session_id:
        return JsonResponse({'error': 'Not authenticated'}, status=401)
    
    try:
        portfolio = Portfolio.objects.get(id=user_id)
        
        # 🔵 SECURE: Verify ownership
        if portfolio.session_id != session_id:
            security_logger.warning(
                f"IDOR blocked: Session {session_id} tried to access portfolio {user_id}"
            )
            return JsonResponse({'error': 'Access denied'}, status=403)
        
        trades = Trade.objects.filter(portfolio=portfolio).values(
            'id', 'trade_type', 'symbol', 'amount', 'price', 'created_at'
        )
        holdings = Holding.objects.filter(portfolio=portfolio).values(
            'id', 'symbol', 'amount', 'average_cost'
        )
        
        return JsonResponse({
            'balance': float(portfolio.balance),
            'trades': list(trades),
            'holdings': list(holdings),
            # 🔵 SECURE: No sensitive data exposed
        })
        
    except Portfolio.DoesNotExist:
        return JsonResponse({'error': 'Not found'}, status=404)


@csrf_protect
@require_http_methods(["DELETE", "POST"])
def secure_trade_delete(request, trade_id):
    """
    🔵 SECURE: Delete trade with ownership verification
    """
    from .models import Trade
    
    session_id = request.session.session_key
    if not session_id:
        return JsonResponse({'error': 'Not authenticated'}, status=401)
    
    try:
        trade = Trade.objects.get(id=trade_id)
        
        # 🔵 SECURE: Verify ownership through portfolio
        if trade.portfolio.session_id != session_id:
            security_logger.warning(
                f"Unauthorized delete attempt: Session {session_id} on trade {trade_id}"
            )
            return JsonResponse({'error': 'Access denied'}, status=403)
        
        trade.delete()
        security_logger.info(f"Trade {trade_id} deleted by session {session_id}")
        return JsonResponse({'success': True})
        
    except Trade.DoesNotExist:
        return JsonResponse({'error': 'Not found'}, status=404)


# ============================================================
# SECURE: AUTHENTICATION
# ============================================================

@csrf_protect
@require_http_methods(["GET", "POST"])
@rate_limit('register', limit=3, period=3600)  # 3 registrations per hour per IP
def secure_register(request):
    """
    🔵 SECURE: User registration with proper password handling
    
    Security controls:
    - Strong password hashing (PBKDF2/Argon2)
    - Password complexity requirements
    - Input validation
    - Rate limiting
    """
    if request.method == 'POST':
        username = request.POST.get('username', '')
        email = request.POST.get('email', '')
        password = request.POST.get('password', '')
        confirm_password = request.POST.get('confirm_password', '')
        
        errors = []
        
        # 🔵 SECURE: Username validation
        if not re.match(r'^[a-zA-Z0-9_]{3,30}$', username):
            errors.append('Username must be 3-30 alphanumeric characters')
        
        # 🔵 SECURE: Email validation
        try:
            validate_email(email)
        except ValidationError:
            errors.append('Invalid email address')
        
        # 🔵 SECURE: Password complexity
        if len(password) < 12:
            errors.append('Password must be at least 12 characters')
        if not re.search(r'[A-Z]', password):
            errors.append('Password must contain uppercase letter')
        if not re.search(r'[a-z]', password):
            errors.append('Password must contain lowercase letter')
        if not re.search(r'\d', password):
            errors.append('Password must contain a number')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append('Password must contain a special character')
        
        # 🔵 SECURE: Password confirmation
        if password != confirm_password:
            errors.append('Passwords do not match')
        
        if errors:
            return render(request, 'secure/register.html', {'errors': errors})
        
        from django.contrib.auth.models import User
        
        # Check if user exists
        if User.objects.filter(username=username).exists():
            return render(request, 'secure/register.html', {
                'errors': ['Username already taken']
            })
        
        # 🔵 SECURE: Proper password hashing with Django's system
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password  # Django automatically hashes this
        )
        
        security_logger.info(f"New user registered: {username}")
        return redirect('/secure/login/')
    
    return render(request, 'secure/register.html')


@csrf_protect
@require_http_methods(["GET", "POST"])
@rate_limit('password_reset', limit=3, period=3600)
def secure_password_reset(request):
    """
    🔵 SECURE: Password reset with secure token
    
    Security controls:
    - Cryptographically secure random token
    - Token expiration
    - Token stored hashed
    - Generic response (no user enumeration)
    """
    if request.method == 'POST':
        email = request.POST.get('email', '')
        
        # 🔵 SECURE: Generate cryptographically secure token
        token = secrets.token_urlsafe(32)
        
        # 🔵 SECURE: Always return same response (prevent user enumeration)
        # In real app, you'd send email if user exists, but don't reveal it
        
        from django.contrib.auth.models import User
        try:
            user = User.objects.get(email=email)
            
            # 🔵 SECURE: Store hashed token with expiration
            from django.core.cache import cache
            token_hash = make_password(token)
            cache.set(f'reset_token:{user.id}', token_hash, 3600)  # 1 hour expiry
            
            # In production: send email with token
            # send_reset_email(user.email, token)
            
            security_logger.info(f"Password reset requested for {email}")
            
        except User.DoesNotExist:
            # 🔵 SECURE: Don't reveal if user exists
            pass
        
        # 🔵 SECURE: Generic response
        return render(request, 'secure/reset.html', {
            'message': 'If an account exists with this email, a reset link has been sent.'
        })
    
    return render(request, 'secure/reset.html')


# ============================================================
# SECURE: FILE UPLOAD
# ============================================================

@csrf_protect
@require_http_methods(["GET", "POST"])
@rate_limit('upload', limit=10, period=3600)
def secure_file_upload(request):
    """
    🔵 SECURE: File upload with proper validation
    
    Security controls:
    - File type whitelist
    - File size limit
    - Filename sanitization
    - Store outside web root
    - Virus scanning (placeholder)
    """
    ALLOWED_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.pdf'}
    MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
    
    if request.method == 'POST' and request.FILES.get('file'):
        uploaded_file = request.FILES['file']
        
        # 🔵 SECURE: Check file size
        if uploaded_file.size > MAX_FILE_SIZE:
            return JsonResponse({'error': 'File too large (max 5MB)'}, status=400)
        
        # 🔵 SECURE: Check file extension
        import os
        _, ext = os.path.splitext(uploaded_file.name)
        if ext.lower() not in ALLOWED_EXTENSIONS:
            security_logger.warning(f"Blocked upload of {ext} file")
            return JsonResponse({
                'error': f'File type not allowed. Allowed: {", ".join(ALLOWED_EXTENSIONS)}'
            }, status=400)
        
        # 🔵 SECURE: Check magic bytes (actual file type)
        file_header = uploaded_file.read(8)
        uploaded_file.seek(0)
        
        # Magic bytes for allowed types
        MAGIC_BYTES = {
            b'\xff\xd8\xff': '.jpg',
            b'\x89PNG\r\n\x1a\n': '.png',
            b'GIF87a': '.gif',
            b'GIF89a': '.gif',
            b'%PDF': '.pdf',
        }
        
        valid_magic = False
        for magic, file_ext in MAGIC_BYTES.items():
            if file_header.startswith(magic) and ext.lower() in [file_ext, '.jpeg']:
                valid_magic = True
                break
        
        if not valid_magic:
            security_logger.warning(f"File type mismatch: claimed {ext}, magic bytes don't match")
            return JsonResponse({'error': 'Invalid file type'}, status=400)
        
        # 🔵 SECURE: Generate random filename
        import uuid
        safe_filename = f"{uuid.uuid4()}{ext.lower()}"
        
        # 🔵 SECURE: Store outside web root
        upload_dir = '/var/uploads/secure/'  # Not web accessible
        os.makedirs(upload_dir, exist_ok=True)
        
        filepath = os.path.join(upload_dir, safe_filename)
        with open(filepath, 'wb') as f:
            for chunk in uploaded_file.chunks():
                f.write(chunk)
        
        # 🔵 In production: scan for viruses here
        # scan_for_viruses(filepath)
        
        security_logger.info(f"File uploaded: {safe_filename}")
        
        return JsonResponse({
            'success': True,
            'file_id': safe_filename.split('.')[0]  # Return ID, not path
        })
    
    return render(request, 'secure/upload.html')


# ============================================================
# SECURE: REDIRECT
# ============================================================

@require_http_methods(["GET"])
def secure_redirect(request):
    """
    🔵 SECURE: Redirect with URL validation
    """
    url = request.GET.get('url', '/')
    
    # 🔵 SECURE: Whitelist allowed domains
    ALLOWED_DOMAINS = [
        'localhost',
        '127.0.0.1',
        'tradeflow.com',
        'www.tradeflow.com',
    ]
    
    from urllib.parse import urlparse
    
    parsed = urlparse(url)
    
    # 🔵 SECURE: Only allow relative URLs or whitelisted domains
    if parsed.netloc and parsed.netloc not in ALLOWED_DOMAINS:
        security_logger.warning(f"Blocked redirect to: {url}")
        return redirect('/')
    
    # 🔵 SECURE: Prevent protocol-relative URLs
    if url.startswith('//'):
        return redirect('/')
    
    return redirect(url)


# ============================================================
# SECURE: SSRF PREVENTION
# ============================================================

@csrf_protect
@require_http_methods(["GET"])
@rate_limit('fetch', limit=10, period=60)
def secure_fetch_url(request):
    """
    🔵 SECURE: URL fetching with SSRF prevention
    """
    import ipaddress
    import socket
    from urllib.parse import urlparse
    import requests
    
    url = request.GET.get('url', '')
    
    if not url:
        return JsonResponse({'error': 'URL required'}, status=400)
    
    # 🔵 SECURE: Parse and validate URL
    try:
        parsed = urlparse(url)
    except:
        return JsonResponse({'error': 'Invalid URL'}, status=400)
    
    # 🔵 SECURE: Only allow http/https
    if parsed.scheme not in ['http', 'https']:
        return JsonResponse({'error': 'Only HTTP(S) allowed'}, status=400)
    
    # 🔵 SECURE: Block internal IPs
    try:
        hostname = parsed.hostname
        ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip)
        
        # Block private, loopback, link-local addresses
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            security_logger.warning(f"SSRF blocked: {url} resolves to {ip}")
            return JsonResponse({'error': 'Internal addresses not allowed'}, status=400)
        
        # Block cloud metadata endpoints
        if ip in ['169.254.169.254', '100.100.100.200']:
            security_logger.warning(f"SSRF blocked: metadata endpoint {url}")
            return JsonResponse({'error': 'Address not allowed'}, status=400)
            
    except socket.gaierror:
        return JsonResponse({'error': 'Could not resolve hostname'}, status=400)
    
    # 🔵 SECURE: Fetch with timeout and size limit
    try:
        response = requests.get(
            url,
            timeout=5,
            allow_redirects=False,  # 🔵 Don't follow redirects (could bypass checks)
            stream=True
        )
        
        # 🔵 SECURE: Limit response size
        content = response.raw.read(1024 * 1024, decode_content=True)  # 1MB max
        
        return JsonResponse({
            'status': response.status_code,
            'content_type': response.headers.get('Content-Type', ''),
            'size': len(content)
        })
        
    except requests.RequestException as e:
        return JsonResponse({'error': 'Request failed'}, status=500)


# ============================================================
# SECURE: COMMAND EXECUTION (AVOID IF POSSIBLE)
# ============================================================

@csrf_protect
@require_http_methods(["GET"])
@rate_limit('ping', limit=5, period=60)
def secure_ping(request):
    """
    🔵 SECURE: Ping with command injection prevention
    
    Best practice: Avoid shell commands entirely if possible
    """
    import subprocess
    import re
    
    host = request.GET.get('host', '')
    
    # 🔵 SECURE: Strict input validation
    # Only allow valid hostnames/IPs
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$', host):
        if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', host):
            return JsonResponse({'error': 'Invalid hostname'}, status=400)
    
    # 🔵 SECURE: Use list arguments, not shell string
    try:
        result = subprocess.run(
            ['ping', '-c', '1', '-W', '2', host],  # 🔵 Arguments as list
            shell=False,  # 🔵 CRITICAL: shell=False
            capture_output=True,
            text=True,
            timeout=5
        )
        
        return JsonResponse({
            'success': result.returncode == 0,
            'output': result.stdout[:500]  # Limit output
        })
        
    except subprocess.TimeoutExpired:
        return JsonResponse({'error': 'Request timed out'}, status=408)
    except Exception as e:
        return JsonResponse({'error': 'Ping failed'}, status=500)


# ============================================================
# SECURE LAB DASHBOARD
# ============================================================

def secure_lab_dashboard(request):
    """Dashboard showing all secure endpoints"""
    
    controls = [
        {
            'vulnerability': 'SQL Injection',
            'control': 'Parameterized Queries',
            'endpoints': ['/secure/login/', '/secure/search/'],
        },
        {
            'vulnerability': 'XSS',
            'control': 'Output Encoding + CSP',
            'endpoints': ['/secure/profile/', '/secure/comment/'],
        },
        {
            'vulnerability': 'IDOR',
            'control': 'Authorization Checks',
            'endpoints': ['/secure/portfolio/<id>/', '/secure/trade/delete/<id>/'],
        },
        {
            'vulnerability': 'Broken Auth',
            'control': 'Strong Hashing + Validation',
            'endpoints': ['/secure/register/', '/secure/password-reset/'],
        },
        {
            'vulnerability': 'File Upload',
            'control': 'Type Validation + Sanitization',
            'endpoints': ['/secure/upload/'],
        },
        {
            'vulnerability': 'Open Redirect',
            'control': 'URL Whitelist',
            'endpoints': ['/secure/redirect/'],
        },
        {
            'vulnerability': 'SSRF',
            'control': 'IP Validation + Blocklist',
            'endpoints': ['/secure/fetch/'],
        },
        {
            'vulnerability': 'Command Injection',
            'control': 'Input Validation + No Shell',
            'endpoints': ['/secure/ping/'],
        },
    ]
    
    return render(request, 'secure/dashboard.html', {'controls': controls})

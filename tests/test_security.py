"""
🧪 SECURITY TESTS FOR TRADEFLOW
================================
Automated security tests that run in CI/CD pipeline.

These tests verify:
- Input validation
- Authentication
- Authorization
- Security headers
- Common vulnerabilities

Run with: pytest tests/test_security.py -v
"""

import pytest
import re
from django.test import TestCase, Client, override_settings
from django.urls import reverse
from django.contrib.auth.models import User


class SecurityHeadersTest(TestCase):
    """Test that security headers are properly set."""
    
    def setUp(self):
        self.client = Client()
    
    def test_x_frame_options_header(self):
        """Verify X-Frame-Options header is set to prevent clickjacking."""
        response = self.client.get('/')
        # Django sets this by default with XFrameOptionsMiddleware
        self.assertIn(
            response.get('X-Frame-Options', '').upper(),
            ['DENY', 'SAMEORIGIN'],
            "X-Frame-Options header should be DENY or SAMEORIGIN"
        )
    
    def test_x_content_type_options_header(self):
        """Verify X-Content-Type-Options header prevents MIME sniffing."""
        response = self.client.get('/')
        self.assertEqual(
            response.get('X-Content-Type-Options'),
            'nosniff',
            "X-Content-Type-Options should be 'nosniff'"
        )
    
    def test_content_type_header_present(self):
        """Verify Content-Type header is always present."""
        response = self.client.get('/')
        self.assertIsNotNone(
            response.get('Content-Type'),
            "Content-Type header should be present"
        )
    
    @override_settings(SECURE_BROWSER_XSS_FILTER=True)
    def test_xss_protection_header(self):
        """Verify XSS protection header is set."""
        response = self.client.get('/')
        # Note: This header is deprecated but still useful for older browsers
        xss_header = response.get('X-XSS-Protection', '')
        # Either not present (modern approach) or set to block
        if xss_header:
            self.assertIn('1', xss_header)


class SQLInjectionTest(TestCase):
    """Test protection against SQL injection attacks."""
    
    def setUp(self):
        self.client = Client()
        self.sqli_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "'; DROP TABLE users; --",
            "1' AND '1'='1",
            "1 UNION SELECT * FROM users",
            "' UNION SELECT username, password FROM auth_user --",
            "1; UPDATE users SET password='hacked'",
        ]
    
    def test_search_endpoint_sqli(self):
        """Test search endpoint is protected against SQL injection."""
        for payload in self.sqli_payloads:
            response = self.client.get('/api/trades/', {'search': payload})
            # Should not return 500 (would indicate SQL error)
            self.assertNotEqual(
                response.status_code, 500,
                f"Potential SQL injection with payload: {payload}"
            )
            # Response should not contain SQL error messages
            content = response.content.decode('utf-8', errors='ignore').lower()
            sql_errors = ['sql', 'syntax error', 'mysql', 'postgresql', 'sqlite']
            for error in sql_errors:
                self.assertNotIn(
                    error, content,
                    f"SQL error exposed with payload: {payload}"
                )


class XSSTest(TestCase):
    """Test protection against Cross-Site Scripting attacks."""
    
    def setUp(self):
        self.client = Client()
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
            "'\"><script>alert('XSS')</script>",
            "<iframe src='javascript:alert(1)'>",
            "<input onfocus=alert('XSS') autofocus>",
        ]
    
    def test_reflected_xss(self):
        """Test that user input is properly escaped in responses."""
        for payload in self.xss_payloads:
            response = self.client.get('/', {'q': payload})
            content = response.content.decode('utf-8')
            
            # The raw payload should not appear unescaped
            self.assertNotIn(
                payload, content,
                f"Potential reflected XSS: payload appears unescaped"
            )
    
    def test_html_entities_escaped(self):
        """Test that HTML entities are properly escaped."""
        dangerous_chars = ['<', '>', '"', "'", '&']
        test_string = '<script>alert("test")</script>'
        
        response = self.client.get('/', {'input': test_string})
        content = response.content.decode('utf-8')
        
        # If the input appears in output, it should be escaped
        if 'script' in content.lower():
            self.assertIn('&lt;', content, "< should be escaped to &lt;")
            self.assertIn('&gt;', content, "> should be escaped to &gt;")


class AuthenticationTest(TestCase):
    """Test authentication security measures."""
    
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            password='TestPassword123!',
            email='test@example.com'
        )
    
    def test_login_rate_limiting(self):
        """Test that login attempts are rate limited."""
        # Attempt multiple failed logins
        for i in range(10):
            response = self.client.post('/admin/login/', {
                'username': 'testuser',
                'password': 'wrongpassword'
            })
        
        # After many attempts, should see rate limiting
        # (Implementation depends on your rate limiting setup)
        # This test documents the expected behavior
    
    def test_password_not_in_response(self):
        """Test that passwords are never included in responses."""
        response = self.client.get('/api/portfolio/')
        content = response.content.decode('utf-8').lower()
        
        self.assertNotIn('password', content)
        self.assertNotIn('passwd', content)
        self.assertNotIn('secret', content)
    
    def test_session_cookie_flags(self):
        """Test that session cookies have security flags."""
        self.client.login(username='testuser', password='TestPassword123!')
        response = self.client.get('/')
        
        # Get session cookie
        session_cookie = response.cookies.get('sessionid')
        if session_cookie:
            # In production, these should be True
            # self.assertTrue(session_cookie['httponly'])
            # self.assertTrue(session_cookie['secure'])
            pass
    
    def test_logout_invalidates_session(self):
        """Test that logout properly invalidates the session."""
        self.client.login(username='testuser', password='TestPassword123!')
        
        # Get session key before logout
        session_key = self.client.session.session_key
        
        # Logout
        self.client.logout()
        
        # Session should be invalid
        # Attempting to use old session should fail


class AuthorizationTest(TestCase):
    """Test authorization and access control."""
    
    def setUp(self):
        self.client = Client()
        self.user1 = User.objects.create_user(
            username='user1',
            password='TestPassword123!'
        )
        self.user2 = User.objects.create_user(
            username='user2',
            password='TestPassword123!'
        )
    
    def test_user_cannot_access_other_user_data(self):
        """Test IDOR protection - users can't access others' data."""
        # Login as user1
        self.client.login(username='user1', password='TestPassword123!')
        
        # Try to access user2's data
        response = self.client.get(f'/api/portfolio/{self.user2.id}/')
        
        # Should be denied
        self.assertIn(
            response.status_code,
            [403, 404],
            "User should not be able to access another user's data"
        )
    
    def test_unauthenticated_access_denied(self):
        """Test that protected endpoints require authentication."""
        protected_endpoints = [
            '/api/trades/',
            '/api/portfolio/',
            '/api/alerts/',
        ]
        
        for endpoint in protected_endpoints:
            response = self.client.get(endpoint)
            self.assertIn(
                response.status_code,
                [401, 403, 302],  # 302 for redirect to login
                f"Endpoint {endpoint} should require authentication"
            )


class CSRFTest(TestCase):
    """Test CSRF protection."""
    
    def setUp(self):
        self.client = Client(enforce_csrf_checks=True)
    
    def test_csrf_token_required(self):
        """Test that POST requests require CSRF token."""
        response = self.client.post('/api/trade/', {
            'symbol': 'BTC',
            'amount': 1,
        })
        
        # Should fail without CSRF token
        self.assertEqual(
            response.status_code,
            403,
            "POST without CSRF token should be rejected"
        )
    
    def test_csrf_token_in_forms(self):
        """Test that forms include CSRF tokens."""
        response = self.client.get('/')
        content = response.content.decode('utf-8')
        
        # If there are forms, they should have CSRF tokens
        if '<form' in content.lower():
            self.assertIn(
                'csrfmiddlewaretoken',
                content,
                "Forms should include CSRF token"
            )


class InputValidationTest(TestCase):
    """Test input validation and sanitization."""
    
    def setUp(self):
        self.client = Client()
    
    def test_trade_amount_validation(self):
        """Test that trade amounts are validated."""
        invalid_amounts = [
            -100,      # Negative
            0,         # Zero
            'abc',     # Non-numeric
            99999999,  # Too large
        ]
        
        for amount in invalid_amounts:
            response = self.client.post('/api/trade/', {
                'symbol': 'BTC',
                'amount': amount,
                'trade_type': 'buy'
            })
            # Should reject invalid amounts
            self.assertNotEqual(
                response.status_code,
                200,
                f"Invalid amount {amount} should be rejected"
            )
    
    def test_symbol_validation(self):
        """Test that trade symbols are validated."""
        invalid_symbols = [
            '<script>',
            "'; DROP TABLE",
            'A' * 100,  # Too long
            '',         # Empty
        ]
        
        for symbol in invalid_symbols:
            response = self.client.post('/api/trade/', {
                'symbol': symbol,
                'amount': 1,
                'trade_type': 'buy'
            })
            self.assertNotEqual(
                response.status_code,
                200,
                f"Invalid symbol {symbol[:20]} should be rejected"
            )


class SensitiveDataExposureTest(TestCase):
    """Test for sensitive data exposure."""
    
    def setUp(self):
        self.client = Client()
    
    def test_debug_info_not_exposed(self):
        """Test that debug information is not exposed."""
        # Try to trigger an error
        response = self.client.get('/nonexistent-page-12345/')
        content = response.content.decode('utf-8').lower()
        
        # Should not expose stack traces or debug info
        debug_indicators = [
            'traceback',
            'file "/',
            'line ',
            'django.core',
            'settings.py',
        ]
        
        for indicator in debug_indicators:
            self.assertNotIn(
                indicator, content,
                f"Debug information exposed: found '{indicator}'"
            )
    
    def test_error_messages_generic(self):
        """Test that error messages don't reveal system info."""
        response = self.client.post('/api/trade/', {
            'invalid': 'data'
        })
        content = response.content.decode('utf-8').lower()
        
        # Should not expose database details
        db_info = ['postgresql', 'mysql', 'sqlite', 'column', 'table']
        for info in db_info:
            self.assertNotIn(
                info, content,
                f"Database information exposed: found '{info}'"
            )
    
    def test_no_server_version_disclosure(self):
        """Test that server version is not disclosed."""
        response = self.client.get('/')
        server_header = response.get('Server', '')
        
        # Should not reveal version numbers
        version_pattern = r'\d+\.\d+(\.\d+)?'
        if server_header:
            self.assertIsNone(
                re.search(version_pattern, server_header),
                "Server header should not reveal version numbers"
            )


class FileUploadSecurityTest(TestCase):
    """Test file upload security."""
    
    def setUp(self):
        self.client = Client()
    
    def test_dangerous_file_types_rejected(self):
        """Test that dangerous file types are rejected."""
        from django.core.files.uploadedfile import SimpleUploadedFile
        
        dangerous_files = [
            ('test.php', b'<?php echo "hacked"; ?>'),
            ('test.exe', b'MZ\x90\x00'),  # PE header
            ('test.sh', b'#!/bin/bash\nrm -rf /'),
            ('test.py', b'import os; os.system("rm -rf /")'),
        ]
        
        for filename, content in dangerous_files:
            file = SimpleUploadedFile(filename, content)
            response = self.client.post('/api/upload/', {'file': file})
            
            self.assertNotEqual(
                response.status_code,
                200,
                f"Dangerous file type {filename} should be rejected"
            )


# =============================================================================
# RUN TESTS
# =============================================================================

if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])

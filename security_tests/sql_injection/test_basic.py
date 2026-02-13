"""
Basic SQL Injection Tester for TradeFlow
Author: David Alicea
Date: February 13, 2026
Purpose: Test TradeFlow for basic SQL injection vulnerabilities
"""

import requests

# Configuration
BASE_URL = "http://127.0.0.1:8000"

# SQL injection payloads to test
PAYLOADS = [
    "' OR '1'='1",
    "admin' --",
    "' OR '1'='1' --",
    "1' OR '1'='1",
    "' OR 'x'='x",
    "admin' OR '1'='1",
]

# SQL error keywords to detect
SQL_ERRORS = [
    'sql syntax',
    'mysql',
    'sqlite',
    'postgresql',
    'syntax error',
    'unclosed quotation',
]

def test_endpoint(url, param_name, payload):
    """Test a single endpoint with a payload"""
    try:
        # Try GET request with payload
        response = requests.get(url, params={param_name: payload}, timeout=5)
        
        # Check for SQL errors in response
        response_lower = response.text.lower()
        for error in SQL_ERRORS:
            if error in response_lower:
                return "VULNERABLE", f"SQL error detected: {error}"
        
        # Check status code
        if response.status_code == 500:
            return "SUSPICIOUS", "500 Internal Server Error"
        
        return "SAFE", "No SQL errors detected"
        
    except Exception as e:
        return "ERROR", str(e)

def main():
    """Main testing function"""
    print("=" * 60)
    print("TradeFlow SQL Injection Tester")
    print("=" * 60)
    print(f"Target: {BASE_URL}")
    print(f"Payloads: {len(PAYLOADS)}")
    print("=" * 60)
    
    # Endpoints to test
    endpoints = [
        ("/", "search"),
        ("/", "q"),
        ("/trading/", "search"),
    ]
    
    results = []
    
    for endpoint, param in endpoints:
        url = BASE_URL + endpoint
        print(f"\n[*] Testing: {url} (param: {param})")
        print("-" * 60)
        
        for payload in PAYLOADS:
            status, message = test_endpoint(url, param, payload)
            
            # Print result
            if status == "VULNERABLE":
                symbol = "[!]"
            elif status == "SUSPICIOUS":
                symbol = "[?]"
            elif status == "SAFE":
                symbol = "[+]"
            else:
                symbol = "[x]"
            
            print(f"  {symbol} {payload[:30]:30} -> {status}: {message}")
            results.append((url, param, payload, status))
    
    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    
    vulnerable = sum(1 for r in results if r[3] == "VULNERABLE")
    suspicious = sum(1 for r in results if r[3] == "SUSPICIOUS")
    safe = sum(1 for r in results if r[3] == "SAFE")
    
    print(f"Total tests: {len(results)}")
    print(f"Vulnerable: {vulnerable}")
    print(f"Suspicious: {suspicious}")
    print(f"Safe: {safe}")
    
    if vulnerable > 0:
        print("\nWARNING: SQL injection vulnerabilities detected!")
        print("Review code and implement parameterized queries.")
    else:
        print("\nNo SQL injection vulnerabilities found.")
        print("Django ORM is protecting the application.")
    
    print("=" * 60)

if __name__ == "__main__":
    main()
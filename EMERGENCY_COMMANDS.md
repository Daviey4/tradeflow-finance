# Emergency Command Reference

## Git Commands (Use Daily)
```bash
# Check status
git status

# Add all changes
git add .

# Commit
git commit -m "security: Day X - what you did"

# Push to GitHub
git push origin main

# If line ending warning appears - IGNORE IT (it's normal on Windows)
```

## Run Django Server
```bash
cd /mnt/c/Users/David\ J/tradeflow-production
python3 manage.py runserver

# Visit: http://127.0.0.1:8000
```

## Run Security Tests
```bash
# SQL Injection test
python3 security_tests/sql_injection/test_basic.py

# Install requests if needed
pip install --break-system-packages requests
```

## Create Database Backup
```bash
cp db.sqlite3 db_backup_$(date +%Y%m%d).sqlite3
```

## LinkedIn Job Search
Search terms:
- "Junior Security Engineer" OR "Associate Security Engineer"
- "Application Security" AND "Junior"
- "Security QA" OR "Security Testing"
- "Python" AND "Security" AND "Junior"

Filters:
- Location: Remote
- Date: Past Week
- Experience: Entry Level

## Cover Letter Template

Subject: Python Engineer Transitioning to Security - [Job Title]

Hi [Name],

I'm a Python Engineer with 4+ years experience actively transitioning 
to security engineering through hands-on penetration testing.

This month I'm:
- Writing Python scripts to test my Django app for SQL injection, XSS, CSRF
- Learning Burp Suite and OWASP ZAP
- Documenting findings in professional pentest reports

Technical foundation:
- 4 years production Python (Django, FastAPI, REST APIs)
- UCF Secure Software Development course (CIS4615)
- Cryptography: Implemented hash functions from scratch
- Built secure trading platform (TradeFlow)

Portfolio: github.com/Daviey4/tradeflow-finance

Can we schedule a brief call to discuss how my background fits 
your team's needs?

Best regards,
David Alicea
(954) 632-0012
aliceadavidj@gmail.com

## Job Application Tracker

Create Google Sheet with columns:
- Date Applied
- Company
- Job Title
- Location
- Salary Range
- Status (Applied / Phone Screen / Interview / Rejected / Offer)
- Follow-up Date
- Notes

## If You Get Stuck

Start new Claude chat with:
"I'm learning security testing. Currently on Day X testing [topic].
My specific question is: [question]
Context: github.com/Daviey4/tradeflow-production"

## Key Files Locations
- Resume: RESUME_UPDATED_2026.md
- Learning Plan: LEARNING_PLAN.md
- Testing Log: security_tests/TESTING_LOG.md
- README: README.md
- This file: EMERGENCY_COMMANDS.md
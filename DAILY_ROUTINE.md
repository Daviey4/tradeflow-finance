# Daily Security Learning Routine

## Morning Session (2 hours)

### Learn (30 min)
- Day 1-2: SQL Injection
  - Video: "SQL Injection Computerphile" on YouTube
  - Take notes in security_tests/sql_injection/NOTES.md

- Day 3-4: XSS (Cross-Site Scripting)
  - Video: "XSS Explained" by LiveOverflow
  - Google XSS Game

- Day 5-6: CSRF Testing
  - OWASP CSRF documentation
  - Test TradeFlow forms

### Test (45 min)
```bash
# Start server
python3 manage.py runserver

# Test manually in browser
# Go to: http://127.0.0.1:8000
# Try payloads in search/input fields
```

### Script (45 min)
```bash
# Run test script
python3 security_tests/sql_injection/test_basic.py

# Document results
# Update: security_tests/TESTING_LOG.md
```

## Afternoon Session (1 hour)

### Apply to Jobs (30 min)
LinkedIn search:
- "Junior Security Engineer" + Remote + Past Week
- "Application Security" + "Junior" + Remote

Apply to 2-3 jobs with:
- Resume: RESUME_UPDATED_2026.md
- Cover letter: Customize template below

### Track Applications (15 min)
Create spreadsheet:
- Company | Job Title | Date Applied | Status | Follow-up Date

### Network (15 min)
- Comment on 2-3 security posts
- Connect with 5 security professionals
- Message: "Hi [Name], I'm transitioning from backend dev to security engineering. Would love to connect!"

## Evening Session (1 hour)

### Document (30 min)
Update TESTING_LOG.md:
- What I learned
- What I tested
- Results
- Next steps

### Commit to GitHub (10 min)
```bash
git add security_tests/
git commit -m "security: Day X - [topic] testing complete"
git push
```

### LinkedIn Post (20 min)
Template:
```
🔐 Day X: [Topic]

Today I learned [topic] by testing my Django app.

What I did:
✅ [specific action]
✅ [specific action]
✅ [specific action]

Results: [what you found]

Key learning: [main insight]

Tomorrow: [next topic]

GitHub: github.com/Daviey4/tradeflow-finance
#CyberSecurity #Python #Security #Learning
```

## Weekly Goals
- 5 days of security learning
- 10-15 job applications
- 5 LinkedIn posts
- 1 comprehensive commit per day
- 1 weekend review/planning session
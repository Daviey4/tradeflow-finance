# =============================================================================
# TRADEFLOW - FREE DEPLOYMENT OPTIONS
# =============================================================================
# Two deployment paths: Railway (easiest) and GCP (best for resume)
# =============================================================================

# =============================================================================
# OPTION 1: RAILWAY (Easiest - Truly Free)
# =============================================================================
# 
# Railway offers:
# - $5 free credit/month (enough for small apps)
# - One-click deploy from GitHub
# - Automatic HTTPS
# - PostgreSQL included free
# - No credit card required initially
#
# DEPLOY IN 2 MINUTES:
# 
# 1. Go to https://railway.app
# 2. Click "Start a New Project"
# 3. Select "Deploy from GitHub repo"
# 4. Select your tradeflow repository
# 5. Railway auto-detects Django and deploys!
# 6. Add PostgreSQL: Click "New" → "Database" → "PostgreSQL"
# 7. Done! You get a URL like: tradeflow-production.up.railway.app
#
# =============================================================================

# =============================================================================
# OPTION 2: RENDER (Also Free)
# =============================================================================
#
# Render offers:
# - 750 hours free/month
# - Spins down after 15 min inactivity (slow cold start)
# - PostgreSQL free for 90 days
#
# DEPLOY:
# 1. Go to https://render.com
# 2. New → Web Service → Connect GitHub
# 3. Select repo
# 4. Build Command: pip install -r requirements.txt
# 5. Start Command: gunicorn tradeflow.wsgi:application
#
# =============================================================================

# =============================================================================
# OPTION 3: GCP CLOUD RUN (Best for Resume - Free*)
# =============================================================================
#
# *Free because:
# - 2 million requests/month free
# - Scales to ZERO (no cost when not used)
# - Only pay when someone visits (pennies)
#
# Great for resume because:
# - Shows GCP experience
# - Matches your Google Cybersecurity cert
# - Enterprise-grade platform
# - Interviewers recognize it
#
# See deploy-gcp.sh for full instructions
#
# =============================================================================

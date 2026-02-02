# 🆓 TradeFlow - FREE Deployment Guide

Get your app live for **$0** in under 5 minutes!

---

## 🏆 Quick Comparison

| Platform | Truly Free? | Cold Start | Best For |
|----------|-------------|------------|----------|
| **Railway** ⭐ | Yes ($5/mo credit) | None | Daily use, demos |
| **Render** | Yes (750 hrs) | 30-60 sec | Portfolio |
| **GCP Cloud Run** | Yes (scales to 0) | 2-5 sec | Resume, interviews |
| **Fly.io** | Yes (3 VMs) | None | Docker fans |

**My Pick: Railway** for keeping it live + **GCP** for resume

---

## 🚂 Option 1: Railway (Recommended - Easiest)

### Step-by-Step (2 minutes)

1. **Push code to GitHub**
```bash
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/YOUR_USERNAME/tradeflow.git
git push -u origin main
```

2. **Go to [railway.app](https://railway.app)**

3. **Click "Start a New Project"**

4. **Select "Deploy from GitHub repo"**

5. **Pick your `tradeflow` repository**

6. **Add Database:**
   - Click "New" → "Database" → "PostgreSQL"
   - Railway auto-connects it!

7. **Add Environment Variables:**
   - Click on your service → "Variables"
   - Add:
     ```
     SECRET_KEY = (click generate)
     DEBUG = False
     DJANGO_SETTINGS_MODULE = tradeflow.settings_production
     ```

8. **Done!** 🎉
   - URL: `https://tradeflow-xxx.up.railway.app`

### Cost: $0
Railway gives $5 free credit/month. Small apps use ~$2-3.

---

## 🎨 Option 2: Render (Also Easy)

### Step-by-Step

1. **Push code to GitHub** (same as above)

2. **Go to [render.com](https://render.com)**

3. **New → Web Service → Connect GitHub**

4. **Configure:**
   ```
   Name: tradeflow
   Environment: Python
   Build Command: pip install -r requirements.txt && python manage.py migrate
   Start Command: gunicorn tradeflow.wsgi:application
   ```

5. **Add PostgreSQL:**
   - New → PostgreSQL → Free tier

6. **Environment Variables:**
   ```
   SECRET_KEY = (generate random string)
   DEBUG = False
   DATABASE_URL = (auto-filled from PostgreSQL)
   ```

7. **Deploy!**

### ⚠️ Note: Render Free Tier
- Spins down after 15 min inactive
- Cold start takes 30-60 seconds
- Good for portfolio, not daily use

---

## ☁️ Option 3: GCP Cloud Run (Best for Resume)

### Why GCP?
- Matches your Google Cybersecurity Certificate
- Impresses interviewers
- Enterprise-grade platform
- Truly scales to zero (free when unused)

### Step-by-Step

1. **Install gcloud CLI:**
   ```bash
   # Mac
   brew install google-cloud-sdk
   
   # Windows - Download from:
   # https://cloud.google.com/sdk/docs/install
   ```

2. **Login & Setup:**
   ```bash
   gcloud auth login
   gcloud projects create tradeflow-app
   gcloud config set project tradeflow-app
   ```

3. **Enable Billing** (required, but won't charge for free tier):
   - Go to: https://console.cloud.google.com/billing
   - Link a card (you get $300 free credit!)

4. **Deploy with ONE command:**
   ```bash
   gcloud run deploy tradeflow \
     --source . \
     --region us-central1 \
     --allow-unauthenticated
   ```

5. **Done!**
   - URL: `https://tradeflow-xxxxx-uc.a.run.app`

### Cost: ~$0
- 2 million requests/month FREE
- Scales to zero when not used
- You only pay if you get real traffic (unlikely for portfolio)

---

## 🔄 Option 4: Deploy to BOTH (My Recommendation)

**Best strategy for job hunting:**

```
Railway (tradeflow.up.railway.app)
├── Always running
├── Fast response
├── Use for: Live demos, sharing with people

GCP Cloud Run (tradeflow-xxx.run.app)  
├── Scales to zero
├── On your resume
├── Use for: Job applications, interviews
```

### Your Resume Says:
```
DEPLOYMENT & CLOUD:
• GCP: Cloud Run, Cloud SQL, Secret Manager
• Railway/Render: Automated CI/CD deployment
• Docker containerization
```

---

## 📋 Environment Variables Needed

All platforms need these:

| Variable | Value | Notes |
|----------|-------|-------|
| `SECRET_KEY` | Random 50+ chars | Generate: `python -c "import secrets; print(secrets.token_urlsafe(50))"` |
| `DEBUG` | `False` | Always False in production |
| `DJANGO_SETTINGS_MODULE` | `tradeflow.settings_production` | Or `settings_gcp` for GCP |
| `DATABASE_URL` | Auto-filled | Most platforms auto-connect |
| `ALLOWED_HOSTS` | Your domain | e.g., `tradeflow-xxx.up.railway.app` |

---

## 🔧 Files You Need

Make sure these exist in your repo:

```
tradeflow/
├── Procfile              # For Railway, Render, Fly.io
├── railway.toml          # Railway-specific config
├── render.yaml           # Render-specific config
├── requirements.txt      # Python dependencies
├── Dockerfile            # For GCP Cloud Run
└── tradeflow/
    ├── settings.py       # Development
    ├── settings_production.py  # Production
    └── settings_gcp.py   # GCP-specific
```

---

## ❓ Which Should You Choose?

```
"I want the easiest deploy"
  → Railway ✅

"I want it always running fast"
  → Railway ✅

"I want GCP on my resume"  
  → GCP Cloud Run ✅

"I want to learn cloud platforms"
  → GCP Cloud Run ✅

"I want both for job hunting"
  → Railway + GCP ✅ (RECOMMENDED)
```

---

## 🚀 Deploy Right Now!

### Fastest Path (Railway):
```bash
# 1. Push to GitHub
git add .
git commit -m "Ready to deploy"
git push

# 2. Go to railway.app
# 3. Connect GitHub
# 4. Select repo
# 5. Done!
```

### For Resume (GCP):
```bash
# 1. Install gcloud
# 2. Run:
gcloud run deploy tradeflow --source . --region us-central1 --allow-unauthenticated
# 3. Done!
```

---

## 💰 Cost Summary

| Platform | Monthly Cost | Notes |
|----------|--------------|-------|
| Railway | **$0** | $5 credit covers small apps |
| Render | **$0** | 750 hrs free (with cold starts) |
| GCP Cloud Run | **$0** | Scales to zero + $300 credit |
| Fly.io | **$0** | 3 free VMs |

**Total cost to have your app live: $0**

---

Good luck with your deployment! 🎉

*Pro tip: Deploy to Railway first (2 min), then GCP later (10 min) when preparing for interviews.*

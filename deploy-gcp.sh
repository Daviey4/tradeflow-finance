# =============================================================================
# TRADEFLOW - GCP DEPLOYMENT GUIDE
# =============================================================================
# Deploy to Google Cloud Platform using Cloud Run
# 
# Why Cloud Run?
# - Serverless (scales to zero = free when not used)
# - Simple deployment (just push container)
# - Automatic HTTPS
# - Integrates with Cloud SQL, Secret Manager
# - Great for portfolios and demos
# =============================================================================

# -----------------------------------------------------------------------------
# QUICK START (5 minutes)
# -----------------------------------------------------------------------------

# 1. Install Google Cloud CLI
# https://cloud.google.com/sdk/docs/install

# 2. Login and set project
gcloud auth login
gcloud config set project YOUR_PROJECT_ID

# 3. Enable required APIs
gcloud services enable \
  cloudbuild.googleapis.com \
  run.googleapis.com \
  sqladmin.googleapis.com \
  secretmanager.googleapis.com \
  artifactregistry.googleapis.com

# 4. Deploy with one command!
gcloud run deploy tradeflow \
  --source . \
  --region us-central1 \
  --allow-unauthenticated

# That's it! You'll get a URL like: https://tradeflow-xxxxx-uc.a.run.app

# -----------------------------------------------------------------------------
# FULL PRODUCTION SETUP
# -----------------------------------------------------------------------------

# === STEP 1: Create Project ===
gcloud projects create tradeflow-prod --name="TradeFlow Production"
gcloud config set project tradeflow-prod

# Enable billing (required for most services)
# Do this in Console: https://console.cloud.google.com/billing

# === STEP 2: Enable APIs ===
gcloud services enable \
  cloudbuild.googleapis.com \
  run.googleapis.com \
  sqladmin.googleapis.com \
  secretmanager.googleapis.com \
  artifactregistry.googleapis.com \
  cloudresourcemanager.googleapis.com \
  iam.googleapis.com \
  compute.googleapis.com

# === STEP 3: Create Artifact Registry (Container Storage) ===
gcloud artifacts repositories create tradeflow \
  --repository-format=docker \
  --location=us-central1 \
  --description="TradeFlow container images"

# === STEP 4: Create Cloud SQL Instance (PostgreSQL) ===
gcloud sql instances create tradeflow-db \
  --database-version=POSTGRES_15 \
  --tier=db-f1-micro \
  --region=us-central1 \
  --storage-size=10GB \
  --storage-type=SSD

# Create database
gcloud sql databases create tradeflow --instance=tradeflow-db

# Create user
gcloud sql users create tradeflow \
  --instance=tradeflow-db \
  --password=YOUR_SECURE_PASSWORD

# === STEP 5: Store Secrets in Secret Manager ===
# Django Secret Key
echo -n "$(python -c 'import secrets; print(secrets.token_urlsafe(50))')" | \
  gcloud secrets create django-secret-key --data-file=-

# Database Password
echo -n "YOUR_SECURE_PASSWORD" | \
  gcloud secrets create db-password --data-file=-

# === STEP 6: Create Service Account ===
gcloud iam service-accounts create tradeflow-sa \
  --display-name="TradeFlow Service Account"

# Grant permissions
PROJECT_ID=$(gcloud config get-value project)

# Cloud SQL access
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:tradeflow-sa@$PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/cloudsql.client"

# Secret Manager access
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:tradeflow-sa@$PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"

# === STEP 7: Build and Push Container ===
# Configure Docker for Artifact Registry
gcloud auth configure-docker us-central1-docker.pkg.dev

# Build and push
docker build -t us-central1-docker.pkg.dev/$PROJECT_ID/tradeflow/app:latest .
docker push us-central1-docker.pkg.dev/$PROJECT_ID/tradeflow/app:latest

# === STEP 8: Deploy to Cloud Run ===
gcloud run deploy tradeflow \
  --image=us-central1-docker.pkg.dev/$PROJECT_ID/tradeflow/app:latest \
  --region=us-central1 \
  --platform=managed \
  --allow-unauthenticated \
  --service-account=tradeflow-sa@$PROJECT_ID.iam.gserviceaccount.com \
  --add-cloudsql-instances=$PROJECT_ID:us-central1:tradeflow-db \
  --set-env-vars="DEBUG=False,DJANGO_SETTINGS_MODULE=tradeflow.settings_gcp" \
  --set-secrets="SECRET_KEY=django-secret-key:latest,DB_PASSWORD=db-password:latest" \
  --memory=512Mi \
  --cpu=1 \
  --min-instances=0 \
  --max-instances=10

# === STEP 9: Run Migrations ===
gcloud run jobs create migrate \
  --image=us-central1-docker.pkg.dev/$PROJECT_ID/tradeflow/app:latest \
  --region=us-central1 \
  --service-account=tradeflow-sa@$PROJECT_ID.iam.gserviceaccount.com \
  --add-cloudsql-instances=$PROJECT_ID:us-central1:tradeflow-db \
  --set-env-vars="DEBUG=False,DJANGO_SETTINGS_MODULE=tradeflow.settings_gcp" \
  --set-secrets="SECRET_KEY=django-secret-key:latest,DB_PASSWORD=db-password:latest" \
  --command="python,manage.py,migrate"

gcloud run jobs execute migrate --region=us-central1

# === STEP 10: Set Up Custom Domain (Optional) ===
# Map your domain
gcloud run domain-mappings create \
  --service=tradeflow \
  --domain=tradeflow.yourdomain.com \
  --region=us-central1

# -----------------------------------------------------------------------------
# COST ESTIMATE
# -----------------------------------------------------------------------------
# 
# Cloud Run:     $0 (scales to zero, free tier: 2M requests/month)
# Cloud SQL:     ~$7/month (db-f1-micro)
# Secret Manager: $0 (free tier: 10,000 access/month)
# Artifact Reg:  ~$0.10/month (storage)
# 
# TOTAL: ~$7-10/month for production
# For demo/portfolio: Essentially FREE (use only when showing)
# -----------------------------------------------------------------------------

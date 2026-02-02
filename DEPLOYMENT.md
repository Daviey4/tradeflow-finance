# TradeFlow - Production Deployment Guide

A complete trading automation platform with web app, mobile app, and security lab.

---

## 🚀 Quick Deployment Options

### Option 1: Deploy to Railway (Easiest - Free Tier)
```bash
# 1. Push code to GitHub
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/YOUR_USERNAME/tradeflow.git
git push -u origin main

# 2. Go to railway.app
# 3. Click "New Project" → "Deploy from GitHub repo"
# 4. Select your repo
# 5. Add PostgreSQL database from "Add Service"
# 6. Set environment variables (see below)
# 7. Done! Railway gives you a free URL
```

### Option 2: Deploy to Render (Free Tier)
```bash
# 1. Push to GitHub
# 2. Go to render.com
# 3. New → Web Service → Connect GitHub
# 4. Select repo
# 5. Build Command: pip install -r requirements.txt && python manage.py migrate
# 6. Start Command: gunicorn tradeflow.wsgi:application
# 7. Add PostgreSQL database
# 8. Set environment variables
```

### Option 3: Deploy to AWS (Production)
```bash
# Using Docker Compose on EC2

# 1. Launch EC2 instance (t3.micro for free tier)
# 2. SSH into instance
ssh -i your-key.pem ec2-user@your-ip

# 3. Install Docker
sudo yum update -y
sudo yum install docker -y
sudo service docker start
sudo usermod -a -G docker ec2-user

# 4. Install Docker Compose
sudo curl -L https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m) -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# 5. Clone your repo
git clone https://github.com/YOUR_USERNAME/tradeflow.git
cd tradeflow

# 6. Create .env file
cat > .env << EOF
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(50))")
DB_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(20))")
ALLOWED_HOSTS=your-domain.com,your-ip
CSRF_TRUSTED_ORIGINS=https://your-domain.com
EOF

# 7. Start everything
docker-compose up -d

# 8. Run migrations
docker-compose exec web python manage.py migrate

# 9. Create admin user
docker-compose exec web python manage.py createsuperuser
```

### Option 4: Deploy to DigitalOcean App Platform
```bash
# 1. Push to GitHub
# 2. Go to cloud.digitalocean.com
# 3. Create App → GitHub → Select repo
# 4. Add Database → PostgreSQL
# 5. Set environment variables
# 6. Deploy
```

---

## 🔧 Environment Variables

Set these in your deployment platform:

```bash
# Required
SECRET_KEY=your-super-secret-key-at-least-50-chars
DATABASE_URL=postgres://user:pass@host:5432/dbname
ALLOWED_HOSTS=your-domain.com,www.your-domain.com
CSRF_TRUSTED_ORIGINS=https://your-domain.com

# Optional
DEBUG=False
REDIS_URL=redis://localhost:6379/0
SECURE_SSL_REDIRECT=True

# For real trading (Alpaca)
ALPACA_API_KEY=your-alpaca-key
ALPACA_SECRET_KEY=your-alpaca-secret
ALPACA_BASE_URL=https://paper-api.alpaca.markets
```

---

## 📱 Mobile App Setup

### Prerequisites
- Node.js 18+
- React Native CLI or Expo
- Xcode (for iOS)
- Android Studio (for Android)

### Using Expo (Easiest)
```bash
# 1. Install Expo
npm install -g expo-cli

# 2. Create new project
npx create-expo-app TradeFlowMobile
cd TradeFlowMobile

# 3. Copy App.js from mobile/ folder

# 4. Install dependencies
npm install @react-navigation/native @react-navigation/bottom-tabs
npm install react-native-screens react-native-safe-area-context
npm install @react-native-async-storage/async-storage

# 5. Update API_BASE_URL in App.js to your deployed server

# 6. Start development
npx expo start

# 7. Scan QR code with Expo Go app on your phone
```

### Using React Native CLI
```bash
# 1. Create project
npx react-native init TradeFlowMobile
cd TradeFlowMobile

# 2. Copy App.js

# 3. Install dependencies
npm install @react-navigation/native @react-navigation/bottom-tabs
npm install react-native-screens react-native-safe-area-context
npm install @react-native-async-storage/async-storage
cd ios && pod install && cd ..

# 4. Run on iOS
npx react-native run-ios

# 5. Run on Android
npx react-native run-android
```

### Publishing to App Stores

**iOS (App Store)**
```bash
# 1. Open in Xcode
open ios/TradeFlowMobile.xcworkspace

# 2. Set up signing (Apple Developer account required - $99/year)
# 3. Archive → Distribute App → App Store Connect
```

**Android (Play Store)**
```bash
# 1. Generate release keystore
keytool -genkeypair -v -storetype PKCS12 -keystore my-upload-key.keystore -alias my-key-alias -keyalg RSA -keysize 2048 -validity 10000

# 2. Build release APK
cd android
./gradlew bundleRelease

# 3. Upload to Play Console (Google Play Developer account - $25 one-time)
```

---

## 🌐 Custom Domain Setup

### With Cloudflare (Recommended)
```bash
# 1. Buy domain on Cloudflare or transfer existing
# 2. Add DNS records:
#    A record: @ → your-server-ip
#    CNAME: www → your-domain.com

# 3. Enable SSL (free)
# 4. Enable "Full (strict)" SSL mode
# 5. Update ALLOWED_HOSTS and CSRF_TRUSTED_ORIGINS
```

### SSL Certificate (Let's Encrypt)
```bash
# On your server
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com -d www.your-domain.com

# Auto-renewal
sudo crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

---

## 📊 Monitoring & Logging

### Sentry (Error Tracking)
```python
# Add to settings_production.py
import sentry_sdk
sentry_sdk.init(
    dsn="your-sentry-dsn",
    traces_sample_rate=0.1,
)
```

### Uptime Monitoring
- Use UptimeRobot (free) or Better Uptime
- Monitor: `https://your-domain.com/health/`

---

## 🔒 Security Checklist

Before going live:

- [ ] Change SECRET_KEY to a secure random value
- [ ] Set DEBUG=False
- [ ] Enable HTTPS (SECURE_SSL_REDIRECT=True)
- [ ] Set proper ALLOWED_HOSTS
- [ ] Set CSRF_TRUSTED_ORIGINS
- [ ] Set up database backups
- [ ] Enable rate limiting
- [ ] Review CORS settings
- [ ] Set secure cookie flags
- [ ] Add security headers (done in nginx.conf)

---

## 💰 Cost Breakdown

| Service | Free Tier | Production |
|---------|-----------|------------|
| Railway | 500 hours/month | $5/month |
| Render | 750 hours/month | $7/month |
| DigitalOcean | $200 credit (60 days) | $12/month |
| AWS EC2 | t3.micro free (12 months) | ~$10/month |
| Domain | - | $10-15/year |
| SSL | Free (Let's Encrypt) | Free |
| **Total** | **$0** | **~$15-25/month** |

---

## 🆘 Troubleshooting

### Database connection error
```bash
# Check DATABASE_URL format
postgres://USER:PASSWORD@HOST:PORT/DATABASE

# Test connection
docker-compose exec web python manage.py dbshell
```

### Static files not loading
```bash
# Collect static files
docker-compose exec web python manage.py collectstatic --noinput
```

### 502 Bad Gateway
```bash
# Check if Django is running
docker-compose logs web

# Restart services
docker-compose restart
```

### CSRF verification failed
```bash
# Add your domain to CSRF_TRUSTED_ORIGINS
CSRF_TRUSTED_ORIGINS=https://your-domain.com,https://www.your-domain.com
```

---

## 📞 Support

- GitHub Issues: [your-repo/issues](https://github.com/YOUR_USERNAME/tradeflow/issues)
- Email: aliceadavidj@gmail.com
- LinkedIn: [David Alicea](https://linkedin.com/in/david-alicea)

---

## 📄 License

MIT License - Feel free to use, modify, and deploy!

---

Built with ❤️ by David Alicea | Security-aware Software Developer

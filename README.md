# 🏦 TradeFlow Finance

**Integrated Trading & Personal Finance Platform with Security-First Architecture**

[![Python](https://img.shields.io/badge/Python-3.10-blue.svg)](https://www.python.org/)
[![Django](https://img.shields.io/badge/Django-4.2-green.svg)](https://www.djangoproject.com/)
[![Security](https://img.shields.io/badge/Security-OWASP%20Top%2010-red.svg)](https://owasp.org/www-project-top-ten/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 📋 Project Overview

TradeFlow Finance is a full-stack web application that combines paper trading simulation with comprehensive personal finance management. Built with security as a priority, it demonstrates DevSecOps practices including OWASP Top 10 compliance, automated security scanning, and secure session management.

**Live Demo:** [Coming Soon - Railway Deployment]  
**Documentation:** [Security Assessment](SECURITY_ASSESSMENT.md) | [Project Status](PROJECT_STATUS.md)

---

## ✨ Key Features

### 💰 Personal Finance Module
- **Transaction Management** - Track expenses with 11 pre-configured categories
- **Budget Tracking** - Set monthly limits with threshold alerts
- **Recurring Transactions** - Automate daily/weekly/monthly expenses
- **Financial Goals** - Monitor savings progress with visual indicators
- **Analytics Dashboard** - Spending breakdown by category

### 📈 Trading Module
- **Paper Trading** - Risk-free trading simulation
- **Portfolio Management** - Real-time position tracking
- **Trade History** - Complete transaction logs
- **Session-Based Demo** - Try without account creation

### 🔒 Security Features
- CSRF protection on all forms
- XSS prevention via template auto-escaping
- SQL injection prevention through Django ORM
- Secure session management
- Input validation and sanitization
- Static security analysis (Bandit)
- Dependency vulnerability scanning (Safety)

---

## 🛠️ Technology Stack

| Category | Technologies |
|----------|-------------|
| **Backend** | Python 3.10, Django 4.2, Django REST Framework |
| **Database** | PostgreSQL with Django ORM |
| **Automation** | Prefect (workflows & scheduling) |
| **Frontend** | Django Templates, Tailwind CSS, Minimal JavaScript |
| **Security** | Bandit, Safety, OWASP ZAP, Django Security |
| **Deployment** | Docker, Railway, GCP Cloud Run |
| **CI/CD** | GitHub Actions (planned) |

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- PostgreSQL 12+
- pip

### Installation
```bash
# Clone repository
git clone https://github.com/yourusername/tradeflow-finance.git
cd tradeflow-finance

# Install dependencies
pip install -r requirements.txt

# Run migrations
python3 manage.py migrate

# Create categories (one-time setup)
python3 manage.py shell
>>> from personal_finance.models import Category
>>> # Categories are auto-created on first migration

# Create superuser
python3 manage.py createsuperuser

# Run development server
python3 manage.py runserver
```

Visit `http://localhost:8000` to access the application.

---

## 📊 Database Schema

### Personal Finance Models
```
Category         Transaction        Budget           FinancialGoal
├── name         ├── user           ├── user         ├── user
├── icon         ├── amount         ├── category     ├── name
└── color        ├── category (FK)  ├── monthly_limit├── target_amount
                 ├── description    └── threshold    ├── current_amount
                 ├── date                            └── target_date
                 ├── is_recurring
                 └── frequency
```

### Trading Models
```
Portfolio        Holding            Trade
├── user         ├── portfolio (FK) ├── portfolio (FK)
├── balance      ├── asset_id       ├── asset_id
└── total_value  ├── symbol         ├── trade_type
                 ├── amount         ├── amount
                 └── avg_cost       ├── price
                                    └── timestamp
```

---

## 🔐 Security Implementation

### OWASP Top 10 Coverage

| Vulnerability | Status | Implementation |
|--------------|--------|----------------|
| A01: Broken Access Control | ✅ | Django auth + permissions |
| A02: Cryptographic Failures | ✅ | Secure defaults, PBKDF2 hashing |
| A03: Injection | ✅ | Django ORM, no raw SQL |
| A04: Insecure Design | ✅ | Security-first architecture |
| A05: Security Misconfiguration | ✅ | Production settings configured |
| A06: Vulnerable Components | ✅ | Dependency scanning with Safety |
| A07: Authentication Failures | ✅ | Django session framework |
| A08: Software Integrity | ✅ | Pinned dependencies |
| A09: Logging Failures | ⏳ | Planned for Phase 2 |
| A10: SSRF | ✅ | No external API calls from input |

### Security Testing
```bash
# Static analysis
bandit -r personal_finance/ trading/

# Dependency scanning
safety check -r requirements.txt

# Django security check
python manage.py check --deploy
```

**Results:** 0 high/medium/low severity issues found  
**Full Report:** [SECURITY_ASSESSMENT.md](SECURITY_ASSESSMENT.md)

---

## 📁 Project Structure
```
tradeflow-production/
├── personal_finance/        # Finance module
│   ├── models.py           # Transaction, Budget, Goal models
│   ├── views.py            # Business logic
│   ├── admin.py            # Admin interface
│   └── templates/          # Django templates
├── trading/                 # Trading module
│   ├── models.py           # Portfolio, Trade models
│   ├── alpaca_trading.py   # Trading logic
│   └── templates/          # Trading UI
├── tradeflow/              # Project settings
│   ├── settings.py         # Configuration
│   ├── settings_production.py
│   └── urls.py             # URL routing
├── requirements.txt        # Dependencies
├── Dockerfile             # Container config
└── docker-compose.yml     # Multi-container setup
```

---

## 🎯 Roadmap

### Phase 1: Core Platform ✅
- [x] Personal finance models
- [x] Database schema design
- [x] Admin interface
- [x] Security assessment

### Phase 2: Web Interface (In Progress)
- [ ] Dashboard views
- [ ] Transaction forms
- [ ] Budget management UI
- [ ] Analytics visualizations

### Phase 3: Automation
- [ ] Prefect workflows for recurring transactions
- [ ] Budget alert notifications
- [ ] Scheduled reports

### Phase 4: API & Mobile
- [ ] REST API endpoints
- [ ] React Native mobile app
- [ ] Google Play Store deployment

### Phase 5: Advanced Features
- [ ] Bank transaction imports (CSV)
- [ ] Multi-currency support
- [ ] Investment tracking integration
- [ ] Advanced analytics & reports

---

## 🧪 Testing
```bash
# Run tests
python3 manage.py test

# Coverage report
coverage run --source='.' manage.py test
coverage report
```

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**David Alicea**
- Email: aliceadavidj@gmail.com
- LinkedIn: [linkedin.com/in/davidalicea](#)
- GitHub: [@davidalicea](#)

---

## 🙏 Acknowledgments

- Django Security Best Practices
- OWASP Top 10 Guidelines
- Tailwind CSS Framework
- Prefect Workflow Engine

---

## 📞 Contact & Support

For questions, issues, or collaboration opportunities:
- Open an issue on GitHub
- Email: aliceadavidj@gmail.com
- LinkedIn: [Connect with me](#)

---

**⭐ If you found this project helpful, please consider giving it a star!**

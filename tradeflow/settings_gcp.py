"""
TradeFlow - GCP Production Settings
====================================
Configured for Google Cloud Platform:
- Cloud Run (serverless)
- Cloud SQL (PostgreSQL)
- Secret Manager (credentials)
- Cloud Storage (static files)
- Cloud Logging
"""

import os
import io
from pathlib import Path

# Try to import Google Cloud libraries
try:
    import google.cloud.secretmanager as secretmanager
    from google.cloud import logging as cloud_logging
    GCP_AVAILABLE = True
except ImportError:
    GCP_AVAILABLE = False

BASE_DIR = Path(__file__).resolve().parent.parent


# =============================================================================
# SECRET MANAGEMENT
# =============================================================================

def get_secret(secret_id, default=None):
    """
    Fetch secret from Google Cloud Secret Manager.
    Falls back to environment variable if not in GCP.
    """
    # First check environment variable
    env_value = os.environ.get(secret_id.upper().replace('-', '_'))
    if env_value:
        return env_value
    
    # Try Secret Manager if available
    if GCP_AVAILABLE:
        try:
            project_id = os.environ.get('GOOGLE_CLOUD_PROJECT') or os.environ.get('GCP_PROJECT_ID')
            if project_id:
                client = secretmanager.SecretManagerServiceClient()
                name = f"projects/{project_id}/secrets/{secret_id}/versions/latest"
                response = client.access_secret_version(request={"name": name})
                return response.payload.data.decode("UTF-8")
        except Exception as e:
            print(f"Warning: Could not fetch secret {secret_id}: {e}")
    
    return default


# =============================================================================
# CORE SETTINGS
# =============================================================================

SECRET_KEY = get_secret('django-secret-key', 'fallback-dev-key-change-in-production')
DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'

# Cloud Run provides the PORT environment variable
PORT = os.environ.get('PORT', '8000')

# Allowed hosts for Cloud Run
ALLOWED_HOSTS = [
    '.run.app',  # Cloud Run default domain
    '.a.run.app',
    'localhost',
    '127.0.0.1',
]

# Add custom domain if set
CUSTOM_DOMAIN = os.environ.get('CUSTOM_DOMAIN')
if CUSTOM_DOMAIN:
    ALLOWED_HOSTS.append(CUSTOM_DOMAIN)
    ALLOWED_HOSTS.append(f'.{CUSTOM_DOMAIN}')

# CSRF trusted origins
CSRF_TRUSTED_ORIGINS = [
    'https://*.run.app',
    'https://*.a.run.app',
]
if CUSTOM_DOMAIN:
    CSRF_TRUSTED_ORIGINS.append(f'https://{CUSTOM_DOMAIN}')
    CSRF_TRUSTED_ORIGINS.append(f'https://*.{CUSTOM_DOMAIN}')


# =============================================================================
# APPLICATION DEFINITION
# =============================================================================

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'corsheaders',
    'rest_framework',
    'trading',
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'trading.security_monitoring.SecurityMonitoringMiddleware',
]

ROOT_URLCONF = 'tradeflow.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'tradeflow.wsgi.application'


# =============================================================================
# DATABASE - Cloud SQL PostgreSQL
# =============================================================================

# Cloud SQL connection via Unix socket (Cloud Run)
# Format: /cloudsql/PROJECT:REGION:INSTANCE

CLOUD_SQL_CONNECTION = os.environ.get('CLOUD_SQL_CONNECTION_NAME')
DB_NAME = os.environ.get('DB_NAME', 'tradeflow')
DB_USER = os.environ.get('DB_USER', 'tradeflow')
DB_PASSWORD = get_secret('db-password', '')

if CLOUD_SQL_CONNECTION:
    # Running on Cloud Run - use Unix socket
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': DB_NAME,
            'USER': DB_USER,
            'PASSWORD': DB_PASSWORD,
            'HOST': f'/cloudsql/{CLOUD_SQL_CONNECTION}',
        }
    }
elif os.environ.get('DATABASE_URL'):
    # Use DATABASE_URL if provided
    import dj_database_url
    DATABASES = {
        'default': dj_database_url.parse(os.environ['DATABASE_URL'])
    }
else:
    # Local development fallback
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }


# =============================================================================
# CACHING - Cloud Memorystore (Redis) or in-memory
# =============================================================================

REDIS_URL = os.environ.get('REDIS_URL')

if REDIS_URL:
    CACHES = {
        'default': {
            'BACKEND': 'django.core.cache.backends.redis.RedisCache',
            'LOCATION': REDIS_URL,
        }
    }
else:
    CACHES = {
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        }
    }


# =============================================================================
# STATIC FILES - Cloud Storage or WhiteNoise
# =============================================================================

STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'

# Use Cloud Storage for production static files (optional)
GCS_BUCKET = os.environ.get('GCS_STATIC_BUCKET')

if GCS_BUCKET:
    # Use Google Cloud Storage
    DEFAULT_FILE_STORAGE = 'storages.backends.gcloud.GoogleCloudStorage'
    STATICFILES_STORAGE = 'storages.backends.gcloud.GoogleCloudStorage'
    GS_BUCKET_NAME = GCS_BUCKET
    GS_DEFAULT_ACL = 'publicRead'
else:
    # Use WhiteNoise for simplicity
    STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

# Media files
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'


# =============================================================================
# SECURITY SETTINGS
# =============================================================================

# HTTPS (Cloud Run handles SSL termination)
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
SECURE_SSL_REDIRECT = True

# Cookies
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True

# Security headers
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True


# =============================================================================
# LOGGING - Cloud Logging Integration
# =============================================================================

# Set up Cloud Logging if available
if GCP_AVAILABLE and os.environ.get('GOOGLE_CLOUD_PROJECT'):
    try:
        client = cloud_logging.Client()
        client.setup_logging()
    except Exception as e:
        print(f"Cloud Logging setup failed: {e}")

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'json': {
            'format': '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "logger": "%(name)s", "message": "%(message)s"}',
        },
        'standard': {
            'format': '[%(asctime)s] %(levelname)s %(name)s: %(message)s',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'json' if not DEBUG else 'standard',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
        'security': {
            'handlers': ['console'],
            'level': 'WARNING',
            'propagate': False,
        },
        'trading': {
            'handlers': ['console'],
            'level': 'DEBUG' if DEBUG else 'INFO',
            'propagate': False,
        },
    },
}


# =============================================================================
# REST FRAMEWORK
# =============================================================================

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticatedOrReadOnly',
    ],
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '100/hour',
        'user': '1000/hour',
    },
}


# =============================================================================
# CORS SETTINGS
# =============================================================================

CORS_ALLOWED_ORIGINS = [
    'https://tradeflow.run.app',
]
if CUSTOM_DOMAIN:
    CORS_ALLOWED_ORIGINS.append(f'https://{CUSTOM_DOMAIN}')

CORS_ALLOW_CREDENTIALS = True


# =============================================================================
# TRADEFLOW SPECIFIC SETTINGS
# =============================================================================

COINGECKO_API_URL = 'https://api.coingecko.com/api/v3'
DEFAULT_BALANCE = 50000.00

# Alpaca Trading (optional)
ALPACA_API_KEY = get_secret('alpaca-api-key', '')
ALPACA_SECRET_KEY = get_secret('alpaca-secret-key', '')
ALPACA_BASE_URL = os.environ.get('ALPACA_BASE_URL', 'https://paper-api.alpaca.markets')


# =============================================================================
# PASSWORD VALIDATION
# =============================================================================

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator', 'OPTIONS': {'min_length': 12}},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]


# =============================================================================
# INTERNATIONALIZATION
# =============================================================================

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

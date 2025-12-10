import os
from pathlib import Path

# Base directories
BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
MODEL_DIR = BASE_DIR
LOGS_DIR = BASE_DIR / "logs"

# Ensure directories exist
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg2://unsub_bot:your_password@localhost:5432/unsub_spam"
)

# Model paths
MODEL_PATHS = {
    'spam_classifier': BASE_DIR / "spam_classifier_model.joblib",
    'vectorizer': MODEL_DIR / "vectorizer.joblib",
    'ensemble_models': MODEL_DIR / "ensemble_models.joblib"
}

# Email configuration
EMAIL_CONFIG = {
    'batch_size': 100,  # Process 100+ emails per run
    'confidence_threshold': 0.85,  # 85%+ accuracy requirement
    'max_retries': 3,
    'timeout': 30
}

# VirusTotal API configuration
VIRUSTOTAL_CONFIG = {
    'api_key': os.getenv('VIRUSTOTAL_API_KEY', ''),
    'base_url': 'https://www.virustotal.com/vtapi/v2/',
    'max_requests_per_minute': 4,  # Free tier limit
    'timeout': 30
}

# URL analysis configuration
URL_ANALYSIS_CONFIG = {
    'max_redirects': 10,
    'timeout': 15,
    'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'phishing_keywords': [
        'urgent', 'immediate', 'click here', 'act now', 'limited time',
        'verify account', 'suspended', 'expires today', 'winner',
        'congratulations', 'free money', 'claim now', 'deposit',
        'wire transfer', 'bitcoin', 'cryptocurrency'
    ],
    'suspicious_tlds': [
        '.tk', '.ml', '.ga', '.cf', '.top', '.click', '.download',
        '.accountant', '.racing', '.cricket', '.science', '.work'
    ]
}

# Spam detection configuration
SPAM_CONFIG = {
    'ensemble_weights': {
        'naive_bayes': 0.4,
        'random_forest': 0.35,
        'logistic_regression': 0.25
    },
    'spam_keywords': [
        'free', 'winner', 'congratulations', 'urgent', 'act now',
        'limited time', 'click here', 'guarantee', 'no risk',
        'money back', 'special promotion', 'exclusive offer',
        'unsubscribe', 'remove', 'opt out', 'viagra', 'pharmacy',
        'loan', 'debt', 'credit', 'investment', 'casino', 'lottery'
    ],
    'ham_indicators': [
        'meeting', 'appointment', 'schedule', 'conference', 'team',
        'project', 'deadline', 'report', 'document', 'invoice',
        'receipt', 'order', 'shipping', 'delivery'
    ]
}

# Logging configuration
LOGGING_CONFIG = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'standard': {
            'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            'encoding': 'utf-8'
        },
    },
    'handlers': {
        'default': {
            'level': 'INFO',
            'formatter': 'standard',
            'class': 'logging.StreamHandler',
        },
        'file': {
            'level': 'DEBUG',
            'formatter': 'standard',
            'class': 'logging.FileHandler',
            'filename': LOGS_DIR / 'unsubspambot.log',
            'mode': 'a',
            'encoding': 'utf-8'
        },
    },
    'loggers': {
        '': {
            'handlers': ['default', 'file'],
            'level': 'DEBUG',
            'propagate': False
        }
    }
}

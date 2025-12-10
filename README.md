# UnsubSpamBot

An intelligent email management system using machine learning to automatically detect spam emails and manage unwanted subscriptions. The system processes 100+ emails per run with 85%+ accuracy using ensemble ML models and comprehensive URL security analysis.

## Features

### Advanced Spam Detection

- **Ensemble ML Models**: Naive Bayes, Random Forest, and Logistic Regression
- **85%+ Accuracy**: Weighted voting system for optimal detection
- **Lightweight Fallback**: Rule-based detection when ML unavailable
- **Continuous Learning**: Model retraining capabilities

### Comprehensive URL Security Analysis

- **VirusTotal Integration**: Real-time threat intelligence
- **Phishing Detection**: Advanced pattern recognition
- **Redirect Chain Analysis**: Track malicious redirects
- **Malicious Domain Detection**: Comprehensive blocklist checking

### Intelligent Email Management

- **Batch Processing**: Handle 100+ emails efficiently
- **Automatic Unsubscription**: Smart unsubscribe from spam sources
- **Database Tracking**: SQLite/MongoDB support for email history
- **Continuous Monitoring**: Real-time email processing

### High Performance

- **Fast Processing**: Optimized for large email volumes
- **Multi-threaded**: Parallel processing capabilities
- **Resource Efficient**: Lightweight design with fallback modes
- **Configurable**: Extensive customization options

## Installation

### Prerequisites

- Python 3.8+
- Email account with IMAP/SMTP access
- Optional: VirusTotal API key for enhanced URL analysis

### Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/UnsubSpamBot.git
cd UnsubSpamBot

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
set EMAIL_USERNAME=your_email@gmail.com
set EMAIL_PASSWORD=your_app_password
set VIRUSTOTAL_API_KEY=your_virustotal_key

# Run initial setup (Windows)
setup_windows.bat

# Or manual setup (Unix/Linux)
python setup.py install
```

## Configuration

### Environment Variables

Create a `.env` file or set these environment variables:

```bash
# Email Configuration (Required)
EMAIL_USERNAME=your_email@gmail.com
EMAIL_PASSWORD=your_app_password

# API Keys (Optional but recommended)
VIRUSTOTAL_API_KEY=your_virustotal_api_key

# Processing Settings
BATCH_SIZE=100
CONFIDENCE_THRESHOLD=0.7
AUTO_UNSUBSCRIBE=true
DAYS_BACK=7

# Advanced Settings
USE_ENSEMBLE=true
URL_ANALYSIS=true
PHISHING_DETECTION=true
CONTINUOUS_MODE=false
CHECK_INTERVAL_HOURS=1
```

## Usage

### Command Line Interface

```bash
# Navigate to src directory
cd src

# Process emails with default settings
python src/main.py process

# Process specific time range without auto-unsubscribe
python src/main.py process --days 14 --no-unsub

# Analyze URL security
python src/main.py analyze-url https://suspicious-site.com

# Test spam detection on text
python src/main.py test-spam "Get rich quick! Click now!"

# Get processing statistics
python src/main.py stats --days 30

# Start continuous monitoring
python src/main.py monitor

# Train model with custom dataset
python src/main.py train data/spam_dataset.csv

# Show current configuration
python src/main.py config
```

---

# Environments

myenv/

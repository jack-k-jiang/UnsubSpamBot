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

# Byte-compiled / optimized / DLL files

**pycache**/
_.py[codz]
_$py.class

# C extensions

\*.so

# Distribution / packaging

.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
share/python-wheels/
_.egg-info/
.installed.cfg
_.egg
MANIFEST

# PyInstaller

# Usually these files are written by a python script from a template

# before PyInstaller builds the exe, so as to inject date/other infos into it.

_.manifest
_.spec

# Installer logs

pip-log.txt
pip-delete-this-directory.txt

# Unit test / coverage reports

htmlcov/
.tox/
.nox/
.coverage
.coverage._
.cache
nosetests.xml
coverage.xml
_.cover
\*.py.cover
.hypothesis/
.pytest_cache/
cover/

# Translations

_.mo
_.pot

# Django stuff:

\*.log
local_settings.py
db.sqlite3
db.sqlite3-journal

# Flask stuff:

instance/
.webassets-cache

# Scrapy stuff:

.scrapy

# Sphinx documentation

docs/\_build/

# PyBuilder

.pybuilder/
target/

# Jupyter Notebook

.ipynb_checkpoints

# IPython

profile_default/
ipython_config.py

# pyenv

# For a library or package, you might want to ignore these files since the code is

# intended to run in multiple environments; otherwise, check them in:

# .python-version

# pipenv

# According to pypa/pipenv#598, it is recommended to include Pipfile.lock in version control.

# However, in case of collaboration, if having platform-specific dependencies or dependencies

# having no cross-platform support, pipenv may install dependencies that don't work, or not

# install all needed dependencies.

#Pipfile.lock

# UV

# Similar to Pipfile.lock, it is generally recommended to include uv.lock in version control.

# This is especially recommended for binary packages to ensure reproducibility, and is more

# commonly ignored for libraries.

#uv.lock

# poetry

# Similar to Pipfile.lock, it is generally recommended to include poetry.lock in version control.

# This is especially recommended for binary packages to ensure reproducibility, and is more

# commonly ignored for libraries.

# https://python-poetry.org/docs/basic-usage/#commit-your-poetrylock-file-to-version-control

#poetry.lock
#poetry.toml

# pdm

# Similar to Pipfile.lock, it is generally recommended to include pdm.lock in version control.

# pdm recommends including project-wide configuration in pdm.toml, but excluding .pdm-python.

# https://pdm-project.org/en/latest/usage/project/#working-with-version-control

#pdm.lock
#pdm.toml
.pdm-python
.pdm-build/

# pixi

# Similar to Pipfile.lock, it is generally recommended to include pixi.lock in version control.

#pixi.lock

# Pixi creates a virtual environment in the .pixi directory, just like venv module creates one

# in the .venv directory. It is recommended not to include this directory in version control.

.pixi

# PEP 582; used by e.g. github.com/David-OConnor/pyflow and github.com/pdm-project/pdm

**pypackages**/

# Celery stuff

celerybeat-schedule
celerybeat.pid

# SageMath parsed files

\*.sage.py

# Environments

.env
.envrc
.venv
env/
venv/
ENV/
env.bak/
venv.bak/

# Spyder project settings

.spyderproject
.spyproject

# Rope project settings

.ropeproject

# mkdocs documentation

/site

# mypy

.mypy_cache/
.dmypy.json
dmypy.json

# Pyre type checker

.pyre/

# pytype static type analyzer

.pytype/

# Cython debug symbols

cython_debug/

# PyCharm

# JetBrains specific template is maintained in a separate JetBrains.gitignore that can

# be found at https://github.com/github/gitignore/blob/main/Global/JetBrains.gitignore

# and can be added to the global gitignore or merged into this file. For a more nuclear

# option (not recommended) you can uncomment the following to ignore the entire idea folder.

#.idea/

# Abstra

# Abstra is an AI-powered process automation framework.

# Ignore directories containing user credentials, local state, and settings.

# Learn more at https://abstra.io/docs

.abstra/

# Visual Studio Code

# Visual Studio Code specific template is maintained in a separate VisualStudioCode.gitignore

# that can be found at https://github.com/github/gitignore/blob/main/Global/VisualStudioCode.gitignore

# and can be added to the global gitignore or merged into this file. However, if you prefer,

# you could uncomment the following to ignore the entire vscode folder

# .vscode/

# Ruff stuff:

.ruff_cache/

# PyPI configuration file

.pypirc

# Cursor

# Cursor is an AI-powered code editor. `.cursorignore` specifies files/directories to

# exclude from AI features like autocomplete and code analysis. Recommended for sensitive data

# refer to https://docs.cursor.com/context/ignore-files

.cursorignore
.cursorindexingignore

# Marimo

marimo/\_static/
marimo/\_lsp/
**marimo**/

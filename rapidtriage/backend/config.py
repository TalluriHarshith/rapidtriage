"""
RapidTriage Backend Configuration
"""

import os
from pathlib import Path

# Base directories
BASE_DIR = Path(__file__).resolve().parent.parent.parent
STORAGE_DIR = BASE_DIR / "storage"
EVIDENCE_DIR = STORAGE_DIR / "evidence"
CASES_DIR = STORAGE_DIR / "cases"
REPORTS_DIR = STORAGE_DIR / "reports"

for dir_path in [STORAGE_DIR, EVIDENCE_DIR, CASES_DIR, REPORTS_DIR]:
    dir_path.mkdir(parents=True, exist_ok=True)

# Database
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{STORAGE_DIR}/rapidtriage.db")

# Default triage analysis parameters
DEFAULT_CORRELATION_WINDOW_MINUTES = 5
DOWNLOAD_EXECUTION_THRESHOLD_MINUTES = 5

# Forensic parameters
APP_NAME = "RapidTriage"
VERSION = "1.0.0"

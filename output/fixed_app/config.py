"""Vibe-coded settings — intentionally insecure for the rescue demo."""

import os

DEBUG = os.environ.get("APP_DEBUG", "false").lower() == "true"
SECRET_KEY = os.environ.get("SECRET_KEY", "DEMO-PLACEHOLDER-dev-only")
ALLOWED_ORIGINS = [
    o.strip()
    for o in os.environ.get("ALLOWED_ORIGINS", "http://localhost:3000").split(",")
    if o.strip()
]
DATABASE_URL = "sqlite:///./app.db"
SESSION_COOKIE_SECURE = False

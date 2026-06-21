"""Hardened settings — secrets from env, safe production defaults."""

import os

DEBUG = os.environ.get("APP_DEBUG", "false").lower() == "true"
SECRET_KEY = os.environ.get("SECRET_KEY", "DEMO-PLACEHOLDER-dev-only")
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.environ.get("ALLOWED_ORIGINS", "http://localhost:3000").split(",")
    if origin.strip()
]
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./app.db")
SESSION_COOKIE_SECURE = True

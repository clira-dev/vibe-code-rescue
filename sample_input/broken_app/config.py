"""Vibe-coded settings — intentionally insecure for the rescue demo."""

DEBUG = True
SECRET_KEY = "DEMO-PLACEHOLDER-insecure-secret"
ALLOW_ALL_ORIGINS = True
DATABASE_URL = "sqlite:///./app.db"
SESSION_COOKIE_SECURE = False

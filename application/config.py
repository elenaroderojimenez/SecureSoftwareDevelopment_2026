import os


BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))


class Config:
    SECRET_KEY = os.urandom(24)
    MAX_CONTENT_LENGTH = 1 * 1024 * 1024
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
    DATABASE = os.path.join(BASE_DIR, "users.db")
    ALLOWED_EXTENSIONS = {"txt", "pdf", "png"}
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = False
    RESET_TOKEN_LIFETIME_MINUTES = 15
    API_TOKEN_LIFETIME_MINUTES = 60
    RESET_LINK_BASE_URL = "http://127.0.0.1:5000"

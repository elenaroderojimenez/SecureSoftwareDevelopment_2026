import os


BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))


class Config:
    SECRET_KEY = os.urandom(24)
    MAX_CONTENT_LENGTH = 1 * 1024 * 1024
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
    DATABASE = os.path.join(BASE_DIR, "users.db")
    ALLOWED_EXTENSIONS = {"txt", "pdf", "png"}

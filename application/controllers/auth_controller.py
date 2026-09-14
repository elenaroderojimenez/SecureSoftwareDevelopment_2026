from functools import wraps
import re
import time

import bcrypt
from flask import flash, redirect, render_template, request, session, url_for

from ..config import Config
from ..models.user_model import (
    create_user,
    email_exists,
    find_password_hash,
    username_exists,
)


MIN_USERNAME_LENGTH = 3
MAX_USERNAME_LENGTH = 30
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 16
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 300
failed_login_attempts = {}


def valid_username(username):
    return re.fullmatch(
        rf"[A-Za-z0-9_]{{{MIN_USERNAME_LENGTH},{MAX_USERNAME_LENGTH}}}", username
    ) is not None


def valid_email(email):
    return re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) is not None


def valid_password(password):
    return (
        MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH
        and any(character.islower() for character in password)
        and any(character.isupper() for character in password)
        and any(character.isdigit() for character in password)
    )


def hash_password(password):
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(password, stored_hash):
    return bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8"))


def login_is_locked(username):
    attempt = failed_login_attempts.get(username)
    if not attempt:
        return False

    if attempt["locked_until"] > time.time():
        return True

    if attempt["locked_until"]:
        failed_login_attempts.pop(username)
    return False


def record_failed_login(username):
    attempt = failed_login_attempts.setdefault(
        username, {"count": 0, "locked_until": 0}
    )
    attempt["count"] += 1

    if attempt["count"] >= MAX_LOGIN_ATTEMPTS:
        attempt["locked_until"] = time.time() + LOCKOUT_SECONDS


def clear_failed_login_attempts(username):
    failed_login_attempts.pop(username, None)


def login_required(view):
    @wraps(view)
    def decorated_function(*args, **kwargs):
        if "logged_in" not in session:
            flash("Access denied. Please log in.")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return decorated_function


def register_auth_routes(app):
    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")

            if not valid_username(username):
                flash(
                    "Error: Username must contain 3-30 letters, numbers, or underscores."
                )
                return redirect(url_for("register"))

            if not valid_email(email):
                flash("Error: Please enter a valid email address.")
                return redirect(url_for("register"))

            if not valid_password(password):
                flash(
                    "Error: Password must be 8-16 characters with uppercase, lowercase, and a number."
                )
                return redirect(url_for("register"))

            if username_exists(Config.DATABASE, username):
                flash("Error: Username already exists.")
                return redirect(url_for("register"))

            if email_exists(Config.DATABASE, email):
                flash("Error: Email already exists.")
                return redirect(url_for("register"))

            password_hash = hash_password(password)
            create_user(Config.DATABASE, username, email, password_hash)
            flash("Registration Successful! Please log in.")
            return redirect(url_for("login"))

        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")

            if login_is_locked(username):
                flash("Too many login attempts. Please try again later.")
                return render_template("login.html")

            record = find_password_hash(Config.DATABASE, username)

            if record and verify_password(password, record[0]):
                clear_failed_login_attempts(username)
                session.clear()
                session["logged_in"] = True
                session["username"] = username
                return redirect(url_for("upload_file"))

            record_failed_login(username)
            flash("Invalid credentials.")

        return render_template("login.html")

    @app.route("/logout")
    def logout():
        session.clear()
        flash("Successfully logged out.")
        return redirect(url_for("login"))

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
    find_session_version,
    find_username_by_email,
    username_exists,
)
from ..models.login_attempt_model import (
    clear_failed_login_attempts,
    login_is_locked,
    record_failed_login,
)
from ..models.password_reset_model import (
    create_reset_token,
    find_valid_reset_token_username,
    reset_password_with_token,
)


MIN_USERNAME_LENGTH = 3
MAX_USERNAME_LENGTH = 30
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 16
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 300
MAX_RESET_REQUESTS = 2
RESET_REQUEST_WINDOW_SECONDS = 3600
BCRYPT_ROUNDS = 12
reset_request_attempts = {}


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
        and any(not character.isalnum() for character in password)
    )


def hash_password(password):
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(password, stored_hash):
    return bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8"))


def reset_request_is_allowed(email):
    now = time.time()
    recent_requests = [
        timestamp
        for timestamp in reset_request_attempts.get(email, [])
        if now - timestamp < RESET_REQUEST_WINDOW_SECONDS
    ]

    if len(recent_requests) >= MAX_RESET_REQUESTS:
        reset_request_attempts[email] = recent_requests
        return False

    recent_requests.append(now)
    reset_request_attempts[email] = recent_requests
    return True


def login_required(view):
    @wraps(view)
    def decorated_function(*args, **kwargs):
        username = session.get("username")
        session_version = session.get("session_version")
        if (
            session.get("logged_in") is True
            and username
            and session_version == find_session_version(Config.DATABASE, username)
        ):
            return view(*args, **kwargs)

        session.clear()
        flash("Access denied. Please log in.")
        return redirect(url_for("login"))

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
                    "Error: Password must be 8-16 characters with uppercase, lowercase, a number, and a symbol."
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

            if login_is_locked(Config.DATABASE, username):
                flash("Too many login attempts. Please wait 5 minutes and try again.")
                return render_template("login.html")

            record = find_password_hash(Config.DATABASE, username)

            if record and verify_password(password, record[0]):
                clear_failed_login_attempts(Config.DATABASE, username)
                session.clear()
                session["logged_in"] = True
                session["username"] = username
                session["session_version"] = find_session_version(
                    Config.DATABASE, username
                )
                return redirect(url_for("upload_file"))

            if record:
                record_failed_login(
                    Config.DATABASE,
                    username,
                    MAX_LOGIN_ATTEMPTS,
                    LOCKOUT_SECONDS,
                )
            flash("Invalid credentials.")

        return render_template("login.html")

    @app.route("/logout")
    def logout():
        session.clear()
        flash("Successfully logged out.")
        return redirect(url_for("login"))

    @app.route("/forgot-password", methods=["GET", "POST"])
    def forgot_password():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()

            # Use the same response whether or not the email is registered.
            if valid_email(email):
                username = find_username_by_email(Config.DATABASE, email)
                if username and reset_request_is_allowed(email):
                    token = create_reset_token(
                        Config.DATABASE,
                        username,
                        Config.RESET_TOKEN_LIFETIME_MINUTES,
                    )
                    reset_path = url_for(
                        "reset_password", token=token
                    )
                    reset_link = f"{Config.RESET_LINK_BASE_URL}{reset_path}"
                    print(f"Development password reset link: {reset_link}")

            flash(
                "If the email exists, a password reset link has been created. "
                "It expires in 15 minutes."
            )
            return redirect(url_for("login"))

        return render_template("forgot_password.html")

    @app.route("/reset-password/<token>", methods=["GET", "POST"])
    def reset_password(token):
        username = find_valid_reset_token_username(Config.DATABASE, token)
        if not username:
            flash("Invalid or expired password reset link.")
            return redirect(url_for("forgot_password"))

        if request.method == "POST":
            password = request.form.get("password", "")
            confirm_password = request.form.get("confirm_password", "")

            if not valid_password(password):
                flash(
                    "Error: Password must be 8-16 characters with uppercase, lowercase, a number, and a symbol."
                )
                return render_template("reset_password.html", token=token)

            if password != confirm_password:
                flash("Error: Passwords do not match.")
                return render_template("reset_password.html", token=token)

            password_hash = hash_password(password)
            if not reset_password_with_token(Config.DATABASE, token, password_hash):
                flash("Invalid or expired password reset link.")
                return redirect(url_for("forgot_password"))

            # Require a new login after changing the password.
            session.clear()
            clear_failed_login_attempts(Config.DATABASE, username)
            flash("Password reset successfully. Please log in.")
            return redirect(url_for("login"))

        return render_template("reset_password.html", token=token)

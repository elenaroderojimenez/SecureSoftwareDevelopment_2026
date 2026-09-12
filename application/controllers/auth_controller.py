from functools import wraps
import re

import bcrypt
from flask import flash, redirect, render_template, request, session, url_for

from ..config import Config
from ..models.user_model import (
    create_user,
    email_exists,
    find_password_hash,
    username_exists,
)


def valid_email(email):
    return re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) is not None


def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(password, stored_hash):
    return bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8"))


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

            if not valid_email(email):
                flash("Error: Please enter a valid email address.")
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
            username = request.form["username"]
            password = request.form["password"]
            record = find_password_hash(Config.DATABASE, username)

            if record and verify_password(password, record[0]):
                session["logged_in"] = True
                session["username"] = username
                return redirect(url_for("upload_file"))

            flash("Invalid credentials.")

        return render_template("login.html")

    @app.route("/logout")
    def logout():
        session.clear()
        flash("Successfully logged out.")
        return redirect(url_for("login"))

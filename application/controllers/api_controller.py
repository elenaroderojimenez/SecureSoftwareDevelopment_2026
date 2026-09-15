import os
import sqlite3
from functools import wraps

import bcrypt
from flask import current_app, jsonify, request, send_from_directory, g

from ..models.api_token_model import (
    create_api_token,
    find_valid_api_token,
    revoke_api_token,
)
from ..models.file_model import create_file, find_owned_file, list_user_files
from ..models.user_model import (
    create_user,
    email_exists,
    find_password_hash,
    find_session_version,
    username_exists,
)
from ..models.login_attempt_model import (
    clear_failed_login_attempts,
    login_is_locked,
    record_failed_login,
)
from .auth_controller import (
    LOCKOUT_SECONDS,
    MAX_LOGIN_ATTEMPTS,
    hash_password,
    valid_email,
    valid_password,
    valid_username,
    verify_password,
)
from .file_controller import (
    allowed_file,
    generate_stored_filename,
    sanitise_filename,
)


def _error(code, message, status):
    return jsonify({"error": code, "message": message}), status


def _bearer_token():
    authorization = request.headers.get("Authorization", "")
    scheme, separator, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not separator or not token.strip():
        return None
    return token.strip()


def api_login_required(view):
    """Authenticate an API request with an active Bearer token."""
    @wraps(view)
    def decorated_function(*args, **kwargs):
        token = _bearer_token()
        if not token:
            response, status = _error(
                "authentication_required",
                "Send an active Bearer token in the Authorization header.",
                401,
            )
            response.headers["WWW-Authenticate"] = "Bearer"
            return response, status

        identity = find_valid_api_token(current_app.config["DATABASE"], token)
        if not identity:
            response, status = _error(
                "invalid_token", "The API token is invalid or expired.", 401
            )
            response.headers["WWW-Authenticate"] = "Bearer"
            return response, status

        username, token_session_version = identity
        current_session_version = find_session_version(
            current_app.config["DATABASE"], username
        )
        if current_session_version is None or token_session_version != current_session_version:
            response, status = _error(
                "invalid_token", "The API token is no longer active.", 401
            )
            response.headers["WWW-Authenticate"] = "Bearer"
            return response, status

        g.api_username = username
        g.api_token = token
        return view(*args, **kwargs)

    return decorated_function


def _json_payload():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return None, _error(
            "invalid_json", "Request body must be a JSON object.", 400
        )
    return payload, None


def register_api_routes(app):
    @app.post("/api/auth/register")
    def api_register():
        payload, error = _json_payload()
        if error:
            return error

        username = payload.get("username", "")
        email = payload.get("email", "")
        password = payload.get("password", "")
        if not all(isinstance(value, str) for value in (username, email, password)):
            return _error("invalid_fields", "All fields must be strings.", 400)

        username = username.strip()
        email = email.strip().lower()
        if not valid_username(username):
            return _error("invalid_username", "Username format is not allowed.", 400)
        if not valid_email(email):
            return _error("invalid_email", "Email format is not allowed.", 400)
        if not valid_password(password):
            return _error("invalid_password", "Password policy was not met.", 400)
        if username_exists(current_app.config["DATABASE"], username) or email_exists(
            current_app.config["DATABASE"], email
        ):
            return _error("account_unavailable", "Username or email is unavailable.", 409)

        try:
            create_user(
                current_app.config["DATABASE"],
                username,
                email,
                hash_password(password),
            )
        except sqlite3.IntegrityError:
            # Return the same response if two registrations race.
            return _error("account_unavailable", "Username or email is unavailable.", 409)

        return jsonify({"username": username, "message": "Account created."}), 201

    @app.post("/api/auth/login")
    def api_login():
        payload, error = _json_payload()
        if error:
            return error

        username = payload.get("username", "")
        password = payload.get("password", "")
        if not isinstance(username, str) or not isinstance(password, str):
            return _error("invalid_fields", "Username and password are required.", 400)
        username = username.strip()

        if login_is_locked(current_app.config["DATABASE"], username):
            return _error("login_temporarily_locked", "Try again later.", 429)

        record = find_password_hash(current_app.config["DATABASE"], username)
        if not record or not verify_password(password, record[0]):
            if record:
                record_failed_login(
                    current_app.config["DATABASE"],
                    username,
                    MAX_LOGIN_ATTEMPTS,
                    LOCKOUT_SECONDS,
                )
            return _error("invalid_credentials", "Invalid credentials.", 401)

        clear_failed_login_attempts(current_app.config["DATABASE"], username)
        session_version = find_session_version(
            current_app.config["DATABASE"], username
        )
        token = create_api_token(
            current_app.config["DATABASE"],
            username,
            session_version,
            current_app.config["API_TOKEN_LIFETIME_MINUTES"],
        )
        response = jsonify(
            {
                "access_token": token,
                "token_type": "Bearer",
                "expires_in": current_app.config["API_TOKEN_LIFETIME_MINUTES"] * 60,
            }
        )
        # Do not cache a response containing a new credential.
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        return response, 200

    @app.post("/api/auth/logout")
    @api_login_required
    def api_logout():
        revoke_api_token(current_app.config["DATABASE"], g.api_token)
        return jsonify({"message": "Token revoked."}), 200

    @app.get("/api/files")
    @api_login_required
    def api_list_files():
        files = list_user_files(
            current_app.config["DATABASE"], g.api_username
        )
        return jsonify({"files": files}), 200

    @app.post("/api/files")
    @api_login_required
    def api_upload_file():
        file = request.files.get("file")
        if not file or not file.filename:
            return _error("file_required", "A file field is required.", 400)
        original_name = sanitise_filename(file.filename)
        if not original_name:
            return _error("invalid_filename", "File name is not valid.", 400)
        if not allowed_file(
            original_name, current_app.config["ALLOWED_EXTENSIONS"]
        ):
            return _error("file_type_not_allowed", "File type is not allowed.", 415)

        stored_name = generate_stored_filename(original_name)
        upload_folder = current_app.config["UPLOAD_FOLDER"]
        os.makedirs(upload_folder, exist_ok=True)
        stored_path = os.path.join(upload_folder, stored_name)
        try:
            file.save(stored_path)
            file_id = create_file(
                current_app.config["DATABASE"],
                original_name,
                stored_name,
                g.api_username,
            )
        except Exception:
            if os.path.exists(stored_path):
                os.remove(stored_path)
            raise

        return jsonify(
            {"id": file_id, "original_name": original_name, "message": "File uploaded."}
        ), 201

    @app.get("/api/files/<int:file_id>")
    @api_login_required
    def api_download_file(file_id):
        record = find_owned_file(
            current_app.config["DATABASE"], file_id, g.api_username
        )
        if not record:
            # Do not disclose whether this file belongs to another user.
            return _error("file_not_found", "File not found.", 404)

        stored_name, original_name = record
        return send_from_directory(
            current_app.config["UPLOAD_FOLDER"],
            stored_name,
            as_attachment=True,
            download_name=original_name,
        )

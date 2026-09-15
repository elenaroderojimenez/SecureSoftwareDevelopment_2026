import sqlite3
from io import BytesIO

import pytest

from application import create_app
from application.config import Config
from application.controllers.auth_controller import hash_password
from application.models.password_reset_model import (
    create_reset_token,
    reset_password_with_token,
)


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(Config, "DATABASE", str(tmp_path / "test_api.db"))
    monkeypatch.setattr(Config, "UPLOAD_FOLDER", str(tmp_path / "uploads"))
    application = create_app()
    application.config.update(TESTING=True)
    return application


@pytest.fixture
def client(app):
    return app.test_client()


def register_and_login(client, username="alice", email="alice@example.com"):
    register_response = client.post(
        "/api/auth/register",
        json={
            "username": username,
            "email": email,
            "password": "Password123!",
        },
    )
    assert register_response.status_code == 201

    login_response = client.post(
        "/api/auth/login",
        json={"username": username, "password": "Password123!"},
    )
    assert login_response.status_code == 200
    return login_response.get_json()["access_token"]


def auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def test_api_register_requires_json(client):
    response = client.post("/api/auth/register", data="not-json")

    assert response.status_code == 400
    assert response.get_json()["error"] == "invalid_json"


def test_api_login_returns_short_lived_bearer_token(client):
    token = register_and_login(client)

    assert isinstance(token, str)
    assert len(token) >= 40

    connection = sqlite3.connect(client.application.config["DATABASE"])
    try:
        stored_token = connection.execute(
            "SELECT token_hash FROM api_tokens"
        ).fetchone()[0]
    finally:
        connection.close()

    assert token != stored_token
    assert len(stored_token) == 64


def test_api_protected_endpoint_rejects_missing_or_invalid_token(client):
    missing = client.get("/api/files")
    invalid = client.get("/api/files", headers=auth_header("not-a-token"))

    assert missing.status_code == 401
    assert missing.get_json()["error"] == "authentication_required"
    assert invalid.status_code == 401
    assert invalid.get_json()["error"] == "invalid_token"
    assert missing.headers["WWW-Authenticate"] == "Bearer"


def test_api_logout_revokes_token(client):
    token = register_and_login(client)
    headers = auth_header(token)

    assert client.get("/api/files", headers=headers).status_code == 200
    logout = client.post("/api/auth/logout", headers=headers)
    after_logout = client.get("/api/files", headers=headers)

    assert logout.status_code == 200
    assert after_logout.status_code == 401


def test_password_reset_invalidates_existing_api_token(client, app):
    token = register_and_login(client)
    reset_token = create_reset_token(app.config["DATABASE"], "alice")

    assert reset_password_with_token(
        app.config["DATABASE"], reset_token, hash_password("NewPassword123!")
    ) is True

    response = client.get("/api/files", headers=auth_header(token))
    assert response.status_code == 401


def test_api_file_access_is_limited_to_owner(app, client):
    alice_token = register_and_login(client)
    upload = client.post(
        "/api/files",
        headers=auth_header(alice_token),
        data={"file": (BytesIO(b"private document"), "document.txt")},
        content_type="multipart/form-data",
    )
    assert upload.status_code == 201
    file_id = upload.get_json()["id"]

    with app.test_client() as bob_client:
        bob_token = register_and_login(
            bob_client, username="bob", email="bob@example.com"
        )
        forbidden = bob_client.get(
            f"/api/files/{file_id}", headers=auth_header(bob_token)
        )

    owned = client.get(
        f"/api/files/{file_id}", headers=auth_header(alice_token)
    )
    listing = client.get("/api/files", headers=auth_header(alice_token))

    assert forbidden.status_code == 404
    assert owned.status_code == 200
    assert owned.data == b"private document"
    assert listing.status_code == 200
    assert listing.get_json()["files"] == [
        {"id": file_id, "original_name": "document.txt"}
    ]

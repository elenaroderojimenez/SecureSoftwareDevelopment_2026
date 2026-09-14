import sqlite3

import bcrypt
import pytest

from application import create_app
from application.config import Config
from application.controllers.auth_controller import failed_login_attempts


@pytest.fixture
def app(tmp_path, monkeypatch):
    database = tmp_path / "test_users.db"
    monkeypatch.setattr(Config, "DATABASE", str(database))
    failed_login_attempts.clear()

    application = create_app()
    application.config.update(TESTING=True)
    return application


@pytest.fixture
def client(app):
    return app.test_client()


def register_user(
    client,
    username="alice",
    email="alice@example.com",
    password="Password123",
):
    return client.post(
        "/register",
        data={
            "username": username,
            "email": email,
            "password": password,
        },
        follow_redirects=True,
    )


def get_users(app):
    connection = sqlite3.connect(app.config["DATABASE"])
    try:
        return connection.execute(
            "SELECT username, email, password_hash FROM users"
        ).fetchall()
    finally:
        connection.close()


def test_register_stores_bcrypt_hash_as_text(client, app):
    # Security requirement: passwords must never be stored in plaintext.
    # Arrange and Act: submit a valid registration.
    register_user(client)

    # Assert: store a text bcrypt hash that verifies the original password.
    users = get_users(app)
    assert len(users) == 1
    username, email, password_hash = users[0]
    assert username == "alice"
    assert email == "alice@example.com"
    assert isinstance(password_hash, str)
    assert password_hash != "Password123"
    assert bcrypt.checkpw(
        b"Password123", password_hash.encode("utf-8")
    )


def test_register_rejects_invalid_email(client, app):
    # Security requirement: email input must be validated on the server.
    register_user(client, email="not-an-email")

    # Assert: malformed input must not create an account.
    assert get_users(app) == []


def test_register_rejects_invalid_username(client, app):
    # Security requirement: usernames must follow a predictable safe format.
    register_user(client, username="invalid username")

    # Assert: whitespace and unsupported characters cannot create an account.
    assert get_users(app) == []


def test_register_rejects_short_password(client, app):
    # Security requirement: weak passwords must be rejected server-side.
    register_user(client, password="short")

    # Assert: a password shorter than the selected eight-character minimum is rejected.
    assert get_users(app) == []


def test_register_rejects_password_without_uppercase_letter(client, app):
    # Security requirement: passwords must include an uppercase letter.
    register_user(client, password="password123")

    # Assert: the account is not created when uppercase is missing.
    assert get_users(app) == []


def test_register_rejects_password_without_lowercase_letter(client, app):
    # Security requirement: passwords must include a lowercase letter.
    register_user(client, password="PASSWORD123")

    # Assert: the account is not created when lowercase is missing.
    assert get_users(app) == []


def test_register_rejects_password_without_number(client, app):
    # Security requirement: passwords must include a number.
    register_user(client, password="PasswordOnly")

    # Assert: the account is not created when a number is missing.
    assert get_users(app) == []


def test_register_rejects_password_longer_than_16_characters(client, app):
    # Security requirement: password length must stay within the defined limit.
    register_user(client, password="Password1" + "a" * 8)

    # Assert: a password longer than 16 characters is rejected.
    assert get_users(app) == []


def test_register_rejects_duplicate_username(client, app):
    # Security requirement: usernames identify one unique account.
    register_user(client)
    register_user(client, email="other@example.com")

    # Assert: the second account must not be created.
    assert len(get_users(app)) == 1


def test_register_rejects_duplicate_email(client, app):
    # Security requirement: one email must not be linked to multiple accounts.
    register_user(client)
    register_user(client, username="other")

    # Assert: the second account must not be created.
    assert len(get_users(app)) == 1


def test_login_accepts_valid_credentials(client):
    # Security requirement: valid credentials must authenticate the user.
    register_user(client)

    response = client.post(
        "/login",
        data={"username": "alice", "password": "Password123"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"File Dashboard" in response.data


def test_login_rejects_wrong_password_without_session(client):
    # Security requirement: an incorrect password must not create a session.
    register_user(client)

    response = client.post(
        "/login",
        data={"username": "alice", "password": "WrongPassword"},
        follow_redirects=True,
    )

    assert b"Invalid credentials." in response.data
    with client.session_transaction() as session:
        assert "logged_in" not in session


def test_login_rejects_unknown_user_without_session(client):
    # Security requirement: unknown accounts must receive the same safe failure path.
    response = client.post(
        "/login",
        data={"username": "unknown", "password": "Password123"},
        follow_redirects=True,
    )

    assert b"Invalid credentials." in response.data
    with client.session_transaction() as session:
        assert "logged_in" not in session


def test_login_blocks_repeated_failed_attempts(client):
    # Security requirement: repeated failed logins must be temporarily blocked.
    register_user(client)

    for _ in range(5):
        client.post(
            "/login",
            data={"username": "alice", "password": "WrongPassword"},
        )

    # Assert: even correct credentials are refused while the lock is active.
    response = client.post(
        "/login",
        data={"username": "alice", "password": "Password123"},
        follow_redirects=True,
    )
    assert b"Too many login attempts." in response.data
    with client.session_transaction() as session:
        assert "logged_in" not in session


def test_protected_route_rejects_anonymous_user(client):
    # Security requirement: unauthenticated users must not access protected resources.
    response = client.get("/")

    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_session_cookie_configuration(app):
    # Security requirement: browser sessions must reduce client-side exposure.
    # Assert: JavaScript cannot read the cookie and same-site protection is enabled.
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"

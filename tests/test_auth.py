import sqlite3
from io import BytesIO
from pathlib import Path

import bcrypt
import pytest

from application import create_app
from application.config import Config


@pytest.fixture
def app(tmp_path, monkeypatch):
    database = tmp_path / "test_users.db"
    monkeypatch.setattr(Config, "DATABASE", str(database))
    monkeypatch.setattr(Config, "UPLOAD_FOLDER", str(tmp_path / "uploads"))

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
    password="Password123!",
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
    register_user(client)

    users = get_users(app)
    assert len(users) == 1
    username, email, password_hash = users[0]
    assert username == "alice"
    assert email == "alice@example.com"
    assert isinstance(password_hash, str)
    assert password_hash != "Password123!"
    assert bcrypt.checkpw(
        b"Password123!", password_hash.encode("utf-8")
    )


def test_register_rejects_invalid_email(client, app):
    register_user(client, email="not-an-email")

    assert get_users(app) == []


def test_register_rejects_invalid_username(client, app):
    register_user(client, username="invalid username")

    assert get_users(app) == []


def test_register_rejects_short_password(client, app):
    register_user(client, password="short")

    assert get_users(app) == []


def test_register_rejects_password_without_uppercase_letter(client, app):
    register_user(client, password="password123")

    assert get_users(app) == []


def test_register_rejects_password_without_lowercase_letter(client, app):
    register_user(client, password="PASSWORD123")

    assert get_users(app) == []


def test_register_rejects_password_without_number(client, app):
    register_user(client, password="PasswordOnly")

    assert get_users(app) == []


def test_register_rejects_password_without_symbol(client, app):
    register_user(client, password="Password123")

    assert get_users(app) == []


def test_register_rejects_password_longer_than_16_characters(client, app):
    register_user(client, password="Password1" + "a" * 8)

    assert get_users(app) == []


def test_register_rejects_duplicate_username(client, app):
    register_user(client)
    register_user(client, email="other@example.com")

    assert len(get_users(app)) == 1


def test_register_rejects_duplicate_email(client, app):
    register_user(client)
    register_user(client, username="other")

    assert len(get_users(app)) == 1


def test_login_accepts_valid_credentials(client):
    register_user(client)

    response = client.post(
        "/login",
        data={"username": "alice", "password": "Password123!"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"File Dashboard" in response.data


def test_login_rejects_wrong_password_without_session(client):
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
    response = client.post(
        "/login",
        data={"username": "unknown", "password": "Password123!"},
        follow_redirects=True,
    )

    assert b"Invalid credentials." in response.data
    with client.session_transaction() as session:
        assert "logged_in" not in session


def test_login_blocks_repeated_failed_attempts(client):
    register_user(client)

    for _ in range(5):
        client.post(
            "/login",
            data={"username": "alice", "password": "WrongPassword"},
        )

    response = client.post(
        "/login",
        data={"username": "alice", "password": "Password123!"},
        follow_redirects=True,
    )
    assert b"Too many login attempts." in response.data
    with client.session_transaction() as session:
        assert "logged_in" not in session


def test_protected_route_rejects_anonymous_user(client):
    response = client.get("/")

    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_session_cookie_configuration(app):
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"


def test_uploads_with_the_same_name_are_stored_separately(client, app):
    """A server-generated identifier must prevent one user's upload replacing another's."""
    register_user(client)
    client.post("/login", data={"username": "alice", "password": "Password123!"})
    first_upload = client.post(
        "/",
        data={"file": (BytesIO(b"alice's document"), "assignment.txt")},
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    with app.test_client() as second_client:
        register_user(
            second_client,
            username="bob",
            email="bob@example.com",
        )
        second_client.post(
            "/login", data={"username": "bob", "password": "Password123!"}
        )
        second_upload = second_client.post(
            "/",
            data={"file": (BytesIO(b"bob's document"), "assignment.txt")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )

    assert b"uploaded successfully." in first_upload.data
    assert b"uploaded successfully." in second_upload.data

    connection = sqlite3.connect(app.config["DATABASE"])
    try:
        files = connection.execute(
            "SELECT owner, original_name, stored_name FROM files ORDER BY owner"
        ).fetchall()
    finally:
        connection.close()

    assert [file[0] for file in files] == ["alice", "bob"]
    assert [file[1] for file in files] == ["assignment.txt", "assignment.txt"]
    assert files[0][2] != files[1][2]
    upload_folder = Path(app.config["UPLOAD_FOLDER"])
    assert (upload_folder / files[0][2]).read_bytes() == b"alice's document"
    assert (upload_folder / files[1][2]).read_bytes() == b"bob's document"


def test_file_search_filters_files_and_escapes_the_query(client):
    """Search must be scoped to the signed-in user and never render HTML input."""
    register_user(client)
    client.post("/login", data={"username": "alice", "password": "Password123!"})
    client.post(
        "/",
        data={"file": (BytesIO(b"notes"), "security-notes.txt")},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    client.post(
        "/",
        data={"file": (BytesIO(b"report"), "report.pdf")},
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    filtered = client.get("/?q=notes")
    assert b"security-notes.txt" in filtered.data
    assert b"report.pdf" not in filtered.data
    assert b"Showing 1 result(s) for:" in filtered.data

    xss_probe = client.get("/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
    assert b"<script>alert(1)</script>" not in xss_probe.data
    assert b"&lt;script&gt;alert(1)&lt;/script&gt;" in xss_probe.data

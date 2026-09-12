from ..database import get_connection


def username_exists(database, username):
    connection = get_connection(database)
    try:
        return connection.execute(
            "SELECT username FROM users WHERE username = ?", (username,)
        ).fetchone() is not None
    finally:
        connection.close()


def email_exists(database, email):
    connection = get_connection(database)
    try:
        return connection.execute(
            "SELECT email FROM users WHERE email = ?", (email,)
        ).fetchone() is not None
    finally:
        connection.close()


def create_user(database, username, email, password_hash):
    connection = get_connection(database)
    try:
        connection.execute(
            """
            INSERT INTO users (username, email, password_hash)
            VALUES (?, ?, ?)
            """,
            (username, email, password_hash),
        )
        connection.commit()
    finally:
        connection.close()


def find_password_hash(database, username):
    connection = get_connection(database)
    try:
        return connection.execute(
            "SELECT password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
    finally:
        connection.close()

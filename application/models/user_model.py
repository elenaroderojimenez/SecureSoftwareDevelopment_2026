from ..database import get_connection


def username_exists(database, username):
    connection = get_connection(database)
    try:
        return connection.execute(
            "SELECT username FROM users WHERE username = ?", (username,)
        ).fetchone() is not None
    finally:
        connection.close()


def create_user(database, username, password_hash, salt):
    connection = get_connection(database)
    try:
        connection.execute(
            """
            INSERT INTO users (username, password_hash, salt)
            VALUES (?, ?, ?)
            """,
            (username, password_hash, salt),
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

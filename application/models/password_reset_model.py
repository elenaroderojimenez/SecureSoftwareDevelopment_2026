import hashlib
import secrets

from ..database import get_connection
from ..config import Config


RESET_TOKEN_BYTES = 32
RESET_TOKEN_LIFETIME_MINUTES = Config.RESET_TOKEN_LIFETIME_MINUTES


def generate_reset_token():
    """Return a cryptographically secure token that is safe to place in a URL."""
    return secrets.token_urlsafe(RESET_TOKEN_BYTES)


def hash_reset_token(token):
    """Return the database representation of a reset token.

    Reset tokens are high-entropy, short-lived secrets. Hashing them prevents a
    database disclosure from immediately exposing a usable reset link.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_reset_token(
    database, username, lifetime_minutes=RESET_TOKEN_LIFETIME_MINUTES
):
    """Create one active token for ``username`` and return its plaintext once.

    Existing unused tokens for the same user are invalidated before the new
    token is stored. Only the SHA-256 hash is persisted.
    """
    if not isinstance(lifetime_minutes, int) or lifetime_minutes <= 0:
        raise ValueError("Token lifetime must be a positive number of minutes.")

    token = generate_reset_token()
    token_hash = hash_reset_token(token)
    expiry_modifier = f"+{lifetime_minutes} minutes"

    connection = get_connection(database)
    try:
        connection.execute(
            "DELETE FROM password_reset_tokens WHERE expires_at <= CURRENT_TIMESTAMP"
        )
        connection.execute(
            "DELETE FROM password_reset_tokens WHERE username = ? AND used_at IS NULL",
            (username,),
        )
        connection.execute(
            """
            INSERT INTO password_reset_tokens (username, token_hash, expires_at)
            VALUES (?, ?, datetime('now', ?))
            """,
            (username, token_hash, expiry_modifier),
        )
        connection.commit()
    finally:
        connection.close()

    return token


def find_valid_reset_token_username(database, token):
    """Return the token owner only when the token is unused and unexpired."""
    token_hash = hash_reset_token(token)
    connection = get_connection(database)
    try:
        record = connection.execute(
            """
            SELECT username
            FROM password_reset_tokens
            WHERE token_hash = ?
              AND used_at IS NULL
              AND expires_at > CURRENT_TIMESTAMP
            """,
            (token_hash,),
        ).fetchone()
        return record[0] if record else None
    finally:
        connection.close()


def consume_reset_token(database, token):
    """Mark a valid token as used and return whether it was consumed."""
    token_hash = hash_reset_token(token)
    connection = get_connection(database)
    try:
        cursor = connection.execute(
            """
            UPDATE password_reset_tokens
            SET used_at = CURRENT_TIMESTAMP
            WHERE token_hash = ?
              AND used_at IS NULL
              AND expires_at > CURRENT_TIMESTAMP
            """,
            (token_hash,),
        )
        connection.commit()
        return cursor.rowcount == 1
    finally:
        connection.close()


def reset_password_with_token(database, token, password_hash):
    """Change a password and consume the token as one SQLite transaction."""
    token_hash = hash_reset_token(token)
    connection = get_connection(database)
    try:
        # Lock the transaction before consuming the token.
        connection.execute("BEGIN IMMEDIATE")
        record = connection.execute(
            """
            SELECT id, username
            FROM password_reset_tokens
            WHERE token_hash = ?
              AND used_at IS NULL
              AND expires_at > CURRENT_TIMESTAMP
            """,
            (token_hash,),
        ).fetchone()

        if not record:
            connection.rollback()
            return False

        token_id, username = record
        connection.execute(
            """
            UPDATE users
            SET password_hash = ?, session_version = session_version + 1
            WHERE username = ?
            """,
            (password_hash, username),
        )
        connection.execute(
            "UPDATE password_reset_tokens SET used_at = CURRENT_TIMESTAMP WHERE id = ?",
            (token_id,),
        )
        connection.commit()
        return True
    finally:
        connection.close()

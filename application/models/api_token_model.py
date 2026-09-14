import hashlib
import secrets

from ..database import get_connection


API_TOKEN_BYTES = 32


def _hash_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_api_token(database, username, session_version, lifetime_minutes):
    """Create a high-entropy API token and return its plaintext once."""
    if not isinstance(lifetime_minutes, int) or lifetime_minutes <= 0:
        raise ValueError("Token lifetime must be a positive number of minutes.")

    token = secrets.token_urlsafe(API_TOKEN_BYTES)
    token_hash = _hash_token(token)
    expiry_modifier = f"+{lifetime_minutes} minutes"

    connection = get_connection(database)
    try:
        connection.execute(
            "DELETE FROM api_tokens WHERE expires_at <= CURRENT_TIMESTAMP OR revoked_at IS NOT NULL"
        )
        connection.execute(
            """
            INSERT INTO api_tokens (username, token_hash, session_version, expires_at)
            VALUES (?, ?, ?, datetime('now', ?))
            """,
            (username, token_hash, session_version, expiry_modifier),
        )
        connection.commit()
    finally:
        connection.close()

    return token


def find_valid_api_token(database, token):
    """Return token identity only when it is active and not expired."""
    token_hash = _hash_token(token)
    connection = get_connection(database)
    try:
        return connection.execute(
            """
            SELECT username, session_version
            FROM api_tokens
            WHERE token_hash = ?
              AND revoked_at IS NULL
              AND expires_at > CURRENT_TIMESTAMP
            """,
            (token_hash,),
        ).fetchone()
    finally:
        connection.close()


def revoke_api_token(database, token):
    """Revoke one token and report whether an active token was changed."""
    token_hash = _hash_token(token)
    connection = get_connection(database)
    try:
        cursor = connection.execute(
            """
            UPDATE api_tokens
            SET revoked_at = CURRENT_TIMESTAMP
            WHERE token_hash = ?
              AND revoked_at IS NULL
            """,
            (token_hash,),
        )
        connection.commit()
        return cursor.rowcount == 1
    finally:
        connection.close()

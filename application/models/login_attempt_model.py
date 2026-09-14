from ..database import get_connection


def login_is_locked(database, username):
    connection = get_connection(database)
    try:
        return connection.execute(
            """
            SELECT 1
            FROM login_attempts
            WHERE username = ? AND locked_until > CURRENT_TIMESTAMP
            """,
            (username,),
        ).fetchone() is not None
    finally:
        connection.close()


def record_failed_login(database, username, max_attempts, lockout_seconds):
    connection = get_connection(database)
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "DELETE FROM login_attempts WHERE updated_at <= datetime('now', '-1 hour')"
        )
        record = connection.execute(
            """
            SELECT failed_attempts, locked_until
            FROM login_attempts
            WHERE username = ?
            """,
            (username,),
        ).fetchone()

        if record and record[1] is None:
            failed_attempts = record[0] + 1
        else:
            failed_attempts = 1

        lockout_modifier = f"+{lockout_seconds} seconds"
        if record:
            connection.execute(
                """
                UPDATE login_attempts
                SET failed_attempts = ?,
                    locked_until = CASE
                        WHEN ? THEN datetime('now', ?)
                        ELSE NULL
                    END,
                    updated_at = CURRENT_TIMESTAMP
                WHERE username = ?
                """,
                (
                    failed_attempts,
                    failed_attempts >= max_attempts,
                    lockout_modifier,
                    username,
                ),
            )
        else:
            connection.execute(
                """
                INSERT INTO login_attempts (username, failed_attempts, locked_until)
                VALUES (?, ?, CASE WHEN ? THEN datetime('now', ?) ELSE NULL END)
                """,
                (
                    username,
                    failed_attempts,
                    failed_attempts >= max_attempts,
                    lockout_modifier,
                ),
            )
        connection.commit()
    finally:
        connection.close()


def clear_failed_login_attempts(database, username):
    connection = get_connection(database)
    try:
        connection.execute("DELETE FROM login_attempts WHERE username = ?", (username,))
        connection.commit()
    finally:
        connection.close()

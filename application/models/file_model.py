from ..database import get_connection


def create_file(database, original_name, stored_name, owner):
    connection = get_connection(database)
    try:
        cursor = connection.execute(
            """
            INSERT INTO files (filename, original_name, stored_name, owner)
            VALUES (?, ?, ?, ?)
            """,
            (stored_name, original_name, stored_name, owner),
        )
        connection.commit()
        return cursor.lastrowid
    finally:
        connection.close()


def list_user_files(database, owner, query=None):
    """Return one user's files, optionally filtered by a literal name fragment."""
    connection = get_connection(database)
    try:
        parameters = [owner]
        where_clause = "WHERE owner = ?"
        if query:
            where_clause += " AND original_name LIKE ?"
            parameters.append(f"%{query}%")

        return [
            {"id": row[0], "original_name": row[1]}
            for row in connection.execute(
                f"""
                SELECT id, original_name FROM files
                {where_clause}
                ORDER BY uploaded_at DESC, id DESC
                """,
                parameters,
            ).fetchall()
        ]
    finally:
        connection.close()


def find_owned_file(database, file_id, owner):
    connection = get_connection(database)
    try:
        return connection.execute(
            """
            SELECT stored_name, original_name FROM files
            WHERE id = ? AND owner = ?
            """,
            (file_id, owner),
        ).fetchone()
    finally:
        connection.close()

from ..database import get_connection


def create_file(database, original_name, stored_name, owner):
    connection = get_connection(database)
    try:
        connection.execute(
            """
            INSERT INTO files (filename, original_name, stored_name, owner)
            VALUES (?, ?, ?, ?)
            """,
            (stored_name, original_name, stored_name, owner),
        )
        connection.commit()
    finally:
        connection.close()


def list_user_files(database, owner):
    connection = get_connection(database)
    try:
        return [
            {"id": row[0], "original_name": row[1]}
            for row in connection.execute(
                """
                SELECT id, original_name FROM files
                WHERE owner = ?
                ORDER BY uploaded_at DESC, id DESC
                """,
                (owner,),
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

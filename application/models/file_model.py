from ..database import get_connection


def create_file(database, filename, owner):
    connection = get_connection(database)
    try:
        connection.execute(
            "INSERT INTO files (filename, owner) VALUES (?, ?)",
            (filename, owner),
        )
        connection.commit()
    finally:
        connection.close()


def list_user_files(database, owner):
    connection = get_connection(database)
    try:
        return [
            row[0]
            for row in connection.execute(
                "SELECT filename FROM files WHERE owner = ?", (owner,)
            ).fetchall()
        ]
    finally:
        connection.close()


def find_owned_file(database, filename, owner):
    connection = get_connection(database)
    try:
        return connection.execute(
            "SELECT * FROM files WHERE filename = ? AND owner = ?",
            (filename, owner),
        ).fetchone()
    finally:
        connection.close()

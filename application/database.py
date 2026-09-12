import os
import sqlite3


def get_connection(database):
    return sqlite3.connect(database)


def initialise_database(database):
    os.makedirs(os.path.dirname(database), exist_ok=True)
    connection = get_connection(database)
    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash BLOB NOT NULL,
                salt BLOB NOT NULL,
                role TEXT NOT NULL DEFAULT 'user'
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                owner TEXT NOT NULL,
                uploaded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(owner) REFERENCES users(username)
            )
            """
        )
        connection.commit()
    finally:
        connection.close()

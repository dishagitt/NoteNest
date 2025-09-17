import sqlite3

DB_NAME = "notes.db"

def get_db_connection():
    """Create and return a database connection."""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row   # makes rows behave like dicts
    return conn

def init_db():
    """Initialize database with required tables."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # users table
    cursor.execute(""" 
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fname TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );
    """)

    # notes table
    cursor.execute(""" 
        CREATE TABLE IF NOT EXISTS mynotes(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            userId INTEGER NOT NULL, 
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            FOREIGN KEY(userId) REFERENCES users(id) ON DELETE CASCADE
        );
    """)

    conn.commit()
    conn.close()

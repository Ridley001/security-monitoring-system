import sqlite3
from datetime import datetime

# This is the name of our database file
DATABASE = 'security.db'

def get_db():
    """Connect to the database and return the connection."""
    conn = sqlite3.connect(DATABASE)
    # This makes rows return as dictionaries (easier to work with)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Create all tables if they don't exist yet."""
    conn = get_db()
    cursor = conn.cursor()

    #  TABLE 1: users 
    # Stores admin login credentials
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            username  TEXT NOT NULL UNIQUE,
            password  TEXT NOT NULL,
            role      TEXT DEFAULT 'admin',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    #TABLE 2: logs 
    # Stores every security event sent from the web app
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            event_type TEXT NOT NULL,
            message    TEXT,
            source     TEXT,
            timestamp  DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    #  TABLE 3: alerts 
    # Stores threats detected by our detection engine
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address  TEXT NOT NULL,
            alert_type  TEXT NOT NULL,
            description TEXT,
            severity    TEXT DEFAULT 'medium',
            status      TEXT DEFAULT 'open',
            timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # TABLE 4: blocked_ips 
    # Stores IPs that have been blocked by the admin
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL UNIQUE,
            reason     TEXT,
            blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    #  TABLE 5: target_systems 
    # Stores the web apps being monitored
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS target_systems (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT NOT NULL,
            url        TEXT NOT NULL,
            status     TEXT DEFAULT 'active',
            added_at   DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    #  DEFAULT ADMIN USER 
    # Creates a default admin account (username: admin, password: admin123)
    # We'll add proper password hashing in Phase 4
    cursor.execute('''
        INSERT OR IGNORE INTO users (username, password, role)
        VALUES ('admin', 'admin123', 'admin')
    ''')

    conn.commit()
    conn.close()
    print("✅ Database initialized successfully!")

# Run this file directly to create the database
if __name__ == '__main__':
    init_db()
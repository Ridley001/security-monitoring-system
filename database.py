import sqlite3
from werkzeug.security import generate_password_hash
from datetime import datetime

# Database file name
DATABASE = 'security.db'

def get_db():
    """Connect to the database and return the connection."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Create all tables if they don't exist yet."""
    conn = get_db()
    cursor = conn.cursor()

    # ── TABLE 1: users ──────────────────────────────────────────
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT NOT NULL UNIQUE,
            password   TEXT NOT NULL,
            role       TEXT DEFAULT 'admin',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # ── TABLE 2: logs ───────────────────────────────────────────
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

    # ── TABLE 3: alerts ─────────────────────────────────────────
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

    # ── TABLE 4: blocked_ips ────────────────────────────────────
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL UNIQUE,
            reason     TEXT,
            blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # ── TABLE 5: target_systems ─────────────────────────────────
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS target_systems (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            name     TEXT NOT NULL,
            url      TEXT NOT NULL,
            status   TEXT DEFAULT 'active',
            added_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # ── TABLE 6: login_attempts ─────────────────────────────────
    # NEW: tracks every login attempt for brute force detection
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            username   TEXT NOT NULL,
            success    INTEGER DEFAULT 0,
            timestamp  DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # ── DEFAULT ADMIN USER (with hashed password) ───────────────
    hashed_password = generate_password_hash('admin123')
    cursor.execute('''
        INSERT OR IGNORE INTO users (username, password, role)
        VALUES (?, ?, 'admin')
    ''', ('admin', hashed_password))

    conn.commit()
    conn.close()
    print("✅ Database initialized successfully!")

if __name__ == '__main__':
    init_db()
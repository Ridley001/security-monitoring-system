from database import get_db

# ═══════════════════════════════════════════════════════════════
#  DETECTION ENGINE
#  Runs after every log is inserted.
#  Checks all rules and creates alerts automatically.
# ═══════════════════════════════════════════════════════════════

def run_detection(ip_address, event_type):
    """
    Main detection function.
    Call this every time a new log is inserted.
    It checks all rules and creates alerts if threats are found.
    """
    check_brute_force(ip_address)
    check_blocked_ip_activity(ip_address)
    check_suspicious_activity(ip_address, event_type)


# ── RULE 1: BRUTE FORCE DETECTION ───────────────────────────────
def check_brute_force(ip_address):
    """
    Rule: If the same IP has more than 5 failed logins
    in the last 60 seconds → create a Brute Force alert.
    """
    db = get_db()

    # Count failed logins from this IP in last 60 seconds
    count = db.execute('''
        SELECT COUNT(*) FROM logs
        WHERE ip_address = ?
        AND   event_type = 'failed_login'
        AND   timestamp >= datetime('now', '-60 seconds')
    ''', (ip_address,)).fetchone()[0]

    if count >= 5:
        # Check if we already have an OPEN brute force alert
        # for this IP — avoid creating duplicate alerts
        existing = db.execute('''
            SELECT id FROM alerts
            WHERE ip_address = ?
            AND   alert_type = 'Brute Force Attack'
            AND   status     = 'open'
            AND   timestamp >= datetime('now', '-60 seconds')
        ''', (ip_address,)).fetchone()

        if not existing:
            db.execute('''
                INSERT INTO alerts
                    (ip_address, alert_type, description, severity, status)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                ip_address,
                'Brute Force Attack',
                f'IP {ip_address} had {count} failed login attempts '
                f'within 60 seconds. Possible brute force attack.',
                'high',
                'open'
            ))
            db.commit()
            print(f'🚨 ALERT: Brute Force detected from {ip_address}')

    db.close()


# ── RULE 2: BLOCKED IP ACTIVITY ──────────────────────────────────
def check_blocked_ip_activity(ip_address):
    """
    Rule: If a blocked IP sends any log at all
    → create a Blocked IP Activity alert.
    """
    db = get_db()

    # Check if this IP is in the blocked list
    is_blocked = db.execute('''
        SELECT id FROM blocked_ips
        WHERE ip_address = ?
    ''', (ip_address,)).fetchone()

    if is_blocked:
        # Avoid duplicate alerts for same IP in last 5 minutes
        existing = db.execute('''
            SELECT id FROM alerts
            WHERE ip_address = ?
            AND   alert_type = 'Blocked IP Activity'
            AND   status     = 'open'
            AND   timestamp >= datetime('now', '-5 minutes')
        ''', (ip_address,)).fetchone()

        if not existing:
            db.execute('''
                INSERT INTO alerts
                    (ip_address, alert_type, description, severity, status)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                ip_address,
                'Blocked IP Activity',
                f'Blocked IP {ip_address} is still sending requests. '
                f'This IP was previously blocked by an admin.',
                'high',
                'open'
            ))
            db.commit()
            print(f'🚨 ALERT: Blocked IP activity detected from {ip_address}')

    db.close()


# ── RULE 3: SUSPICIOUS ACTIVITY ──────────────────────────────────
def check_suspicious_activity(ip_address, event_type):
    """
    Rule: If any log has event_type = suspicious_activity
    → create a Suspicious Activity alert.
    """
    if event_type != 'suspicious_activity':
        return

    db = get_db()

    # Avoid duplicate alerts for same IP in last 5 minutes
    existing = db.execute('''
        SELECT id FROM alerts
        WHERE ip_address = ?
        AND   alert_type = 'Suspicious Activity'
        AND   status     = 'open'
        AND   timestamp >= datetime('now', '-5 minutes')
    ''', (ip_address,)).fetchone()

    if not existing:
        db.execute('''
            INSERT INTO alerts
                (ip_address, alert_type, description, severity, status)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            ip_address,
            'Suspicious Activity',
            f'Suspicious activity detected from IP {ip_address}. '
            f'Manual review recommended.',
            'medium',
            'open'
        ))
        db.commit()
        print(f'⚠️  ALERT: Suspicious activity from {ip_address}')

    db.close()
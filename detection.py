from database import get_db


def run_detection(ip_address, event_type):
    """Run all detection rules after every log insert."""
    db = get_db()
    try:
        _rule_brute_force(db, ip_address)
        _rule_blocked_ip(db, ip_address)
        _rule_suspicious(db, ip_address, event_type)
        _rule_wordpress(db, ip_address)
    finally:
        db.close()


# ══════════════════════════════════════════════════════════════
#  RULES
# ══════════════════════════════════════════════════════════════

def _rule_brute_force(db, ip):
    count = db.execute('''
        SELECT COUNT(*) FROM logs
        WHERE ip_address = ?
        AND event_type = 'failed_login'
        AND timestamp >= datetime('now', '-60 seconds')
    ''', (ip,)).fetchone()[0]

    if count >= 5:
        _alert_if_new(
            db, ip,
            'Brute Force Attack', 'high',
            f'{count} failed login attempts from {ip} '
            f'in 60 seconds.',
            window=5
        )


def _rule_blocked_ip(db, ip):
    blocked = db.execute(
        'SELECT id FROM blocked_ips WHERE ip_address = ?',
        (ip,)
    ).fetchone()

    if blocked:
        _alert_if_new(
            db, ip,
            'Blocked IP Activity', 'high',
            f'Blocked IP {ip} is attempting access.',
            window=10
        )


def _rule_suspicious(db, ip, event_type):
    if event_type != 'suspicious_activity':
        return

    # Get the latest suspicious log message
    row = db.execute('''
        SELECT message FROM logs
        WHERE ip_address = ?
        AND event_type = 'suspicious_activity'
        ORDER BY timestamp DESC LIMIT 1
    ''', (ip,)).fetchone()

    msg = row['message'] if row else \
          f'Suspicious activity from {ip}'

    # ── Large Transfer → ALWAYS create a new alert ────────────
    # No dedup — every large transfer is a distinct event
    if msg and 'LARGE TRANSFER' in msg.upper():
        _alert_always(
            db, ip,
            'Large Transfer Alert', 'high',
            msg
        )
    else:
        # Regular suspicious activity — dedup 3 min
        _alert_if_new(
            db, ip,
            'Suspicious Activity', 'medium',
            msg,
            window=3
        )


def _rule_wordpress(db, ip):
    count = db.execute('''
        SELECT COUNT(*) FROM logs
        WHERE ip_address = ?
        AND source = 'wordpress'
        AND event_type = 'failed_login'
        AND timestamp >= datetime('now', '-60 seconds')
    ''', (ip,)).fetchone()[0]

    if count >= 3:
        _alert_if_new(
            db, ip,
            'WordPress Brute Force', 'high',
            f'{count} failed WordPress login attempts '
            f'from {ip}.',
            window=5
        )


# ══════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════

def _alert_if_new(db, ip, alert_type, severity,
                   message, window=5):
    """Create alert only if none exists in last N minutes."""
    existing = db.execute('''
        SELECT id FROM alerts
        WHERE ip_address = ?
        AND alert_type   = ?
        AND timestamp   >= datetime('now',
                          ? || ' minutes')
    ''', (ip, alert_type, f'-{window}')).fetchone()

    if not existing:
        _insert(db, ip, alert_type, severity, message)


def _alert_always(db, ip, alert_type, severity, message):
    """Always create a new alert — no dedup at all."""
    _insert(db, ip, alert_type, severity, message)


def _insert(db, ip, alert_type, severity, message):
    """Insert alert row, commit, and fire email."""
    db.execute('''
        INSERT INTO alerts
            (ip_address, alert_type, severity, message)
        VALUES (?, ?, ?, ?)
    ''', (ip, alert_type, severity, message))
    db.commit()

    print(f'🚨 ALERT: [{severity.upper()}] '
          f'{alert_type} — {ip}')

    # Email notification (non-blocking)
    try:
        from app import send_email_notification
        send_email_notification(
            subject    = (f'🚨 SecureWatch: {alert_type} '
                          f'[{severity.upper()}]'),
            body       = message,
            alert_type = alert_type,
            severity   = severity,
            ip_address = ip
        )
    except Exception as e:
        print(f'Email error: {e}')
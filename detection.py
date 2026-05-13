from database import get_db
from datetime import datetime, timedelta


def run_detection(ip_address, event_type):
    """
    Run all detection rules against the latest activity.
    Creates alerts and triggers email notifications when
    threats are detected.
    """
    db = get_db()

    # ── RULE 1: Brute Force ──────────────────────────────────────
    # 5+ failed logins from same IP in 60 seconds
    failed_count = db.execute('''
        SELECT COUNT(*) FROM logs
        WHERE ip_address = ?
        AND event_type   = 'failed_login'
        AND timestamp    >= datetime('now', '-60 seconds')
    ''', (ip_address,)).fetchone()[0]

    if failed_count >= 5:
        already = db.execute('''
            SELECT id FROM alerts
            WHERE ip_address = ?
            AND alert_type   = 'Brute Force Attack'
            AND timestamp    >= datetime('now', '-5 minutes')
        ''', (ip_address,)).fetchone()

        if not already:
            db.execute('''
                INSERT INTO alerts
                    (ip_address, alert_type, severity, message)
                VALUES (?, ?, ?, ?)
            ''', (
                ip_address,
                'Brute Force Attack',
                'high',
                f'{failed_count} failed login attempts '
                f'from {ip_address} in 60 seconds.'
            ))
            db.commit()
            _notify(
                ip_address,
                'Brute Force Attack',
                'high',
                f'{failed_count} failed login attempts '
                f'in 60 seconds'
            )

    # ── RULE 2: Blocked IP Activity ──────────────────────────────
    is_blocked = db.execute('''
        SELECT id FROM blocked_ips
        WHERE ip_address = ?
    ''', (ip_address,)).fetchone()

    if is_blocked:
        already = db.execute('''
            SELECT id FROM alerts
            WHERE ip_address = ?
            AND alert_type   = 'Blocked IP Activity'
            AND timestamp    >= datetime('now', '-10 minutes')
        ''', (ip_address,)).fetchone()

        if not already:
            db.execute('''
                INSERT INTO alerts
                    (ip_address, alert_type, severity, message)
                VALUES (?, ?, ?, ?)
            ''', (
                ip_address,
                'Blocked IP Activity',
                'high',
                f'Blocked IP {ip_address} is still '
                f'attempting to access the system.'
            ))
            db.commit()
            _notify(
                ip_address,
                'Blocked IP Activity',
                'high',
                f'Blocked IP {ip_address} is attempting '
                f'access'
            )

    # ── RULE 3: Suspicious Activity ──────────────────────────────
    if event_type == 'suspicious_activity':
        already = db.execute('''
            SELECT id FROM alerts
            WHERE ip_address = ?
            AND alert_type   = 'Suspicious Activity'
            AND timestamp    >= datetime('now', '-5 minutes')
        ''', (ip_address,)).fetchone()

        if not already:
            # Get the latest message for context
            latest = db.execute('''
                SELECT message FROM logs
                WHERE ip_address = ?
                AND event_type   = 'suspicious_activity'
                ORDER BY timestamp DESC LIMIT 1
            ''', (ip_address,)).fetchone()
            msg = latest['message'] if latest else \
                f'Suspicious activity from {ip_address}'

            db.execute('''
                INSERT INTO alerts
                    (ip_address, alert_type, severity, message)
                VALUES (?, ?, ?, ?)
            ''', (
                ip_address,
                'Suspicious Activity',
                'medium',
                msg
            ))
            db.commit()
            _notify(
                ip_address,
                'Suspicious Activity',
                'medium',
                msg
            )

    # ── RULE 4: Large Transfer Flag ───────────────────────────────
    if event_type == 'suspicious_activity':
        latest_log = db.execute('''
            SELECT message FROM logs
            WHERE ip_address = ?
            AND event_type   = 'suspicious_activity'
            ORDER BY timestamp DESC LIMIT 1
        ''', (ip_address,)).fetchone()

        if latest_log and 'LARGE TRANSFER' in (
                latest_log['message'] or ''):
            already = db.execute('''
                SELECT id FROM alerts
                WHERE ip_address = ?
                AND alert_type   = 'Large Transfer Alert'
                AND timestamp    >= datetime('now',
                                            '-2 minutes')
            ''', (ip_address,)).fetchone()

            if not already:
                db.execute('''
                    INSERT INTO alerts
                        (ip_address, alert_type,
                         severity, message)
                    VALUES (?, ?, ?, ?)
                ''', (
                    ip_address,
                    'Large Transfer Alert',
                    'high',
                    latest_log['message']
                ))
                db.commit()
                _notify(
                    ip_address,
                    'Large Transfer Alert',
                    'high',
                    latest_log['message']
                )

    db.close()


def _notify(ip_address, alert_type, severity, message):
    """
    Import and call the email function from app context.
    Uses lazy import to avoid circular imports.
    """
    try:
        from app import send_email_notification
        subject = (
            f'🚨 SecureWatch Alert: '
            f'{alert_type} — {severity.upper()}'
        )
        send_email_notification(
            subject    = subject,
            body       = message,
            alert_type = alert_type,
            severity   = severity,
            ip_address = ip_address
        )
    except Exception as e:
        print(f'Notification error: {e}')
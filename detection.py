import smtplib
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from database import get_db


def run_detection(ip_address, event_type):
    """Run all detection rules after every log insert."""
    try:
        db = get_db()
        _rule_brute_force(db, ip_address)
        _rule_blocked_ip(db, ip_address)
        _rule_suspicious(db, ip_address, event_type)
        _rule_wordpress(db, ip_address)
        db.close()
    except Exception as e:
        print(f'[DETECTION ERROR] {e}')


# ══════════════════════════════════════════════════════════════
#  RULES
# ══════════════════════════════════════════════════════════════

def _rule_brute_force(db, ip):
    """
    Trigger if same IP has 3+ failed logins ever recorded.
    No time window — counts ALL failed logins from that IP.
    This guarantees it fires regardless of timestamp issues.
    """
    try:
        count = db.execute('''
            SELECT COUNT(*) FROM logs
            WHERE ip_address = ?
            AND event_type = 'failed_login'
        ''', (ip,)).fetchone()[0]

        print(f'[DETECTION] Brute force check: '
              f'{ip} has {count} failed logins')

        if count >= 3:
            _alert_if_new(
                db, ip,
                'Brute Force Attack', 'high',
                f'{count} failed login attempts '
                f'detected from IP {ip}.',
                window_count=1
            )
    except Exception as e:
        print(f'[BRUTE FORCE ERROR] {e}')


def _rule_blocked_ip(db, ip):
    """Alert when a blocked IP accesses the system."""
    try:
        blocked = db.execute(
            'SELECT id FROM blocked_ips '
            'WHERE ip_address = ?',
            (ip,)
        ).fetchone()

        if blocked:
            _alert_if_new(
                db, ip,
                'Blocked IP Activity', 'high',
                f'Blocked IP {ip} is attempting '
                f'to access the system.',
                window_count=1
            )
    except Exception as e:
        print(f'[BLOCKED IP ERROR] {e}')


def _rule_suspicious(db, ip, event_type):
    """Alert on suspicious_activity events."""
    try:
        if event_type != 'suspicious_activity':
            return

        row = db.execute('''
            SELECT message FROM logs
            WHERE ip_address = ?
            AND event_type = 'suspicious_activity'
            ORDER BY id DESC LIMIT 1
        ''', (ip,)).fetchone()

        msg = row['message'] if row else \
              f'Suspicious activity detected from {ip}'

        print(f'[DETECTION] Suspicious activity: '
              f'{ip} — {msg[:60]}')

        if msg and 'LARGE TRANSFER' in msg.upper():
            # Every large transfer = new alert, no dedup
            _insert(db, ip,
                    'Large Transfer Alert',
                    'high', msg)
        else:
            _alert_if_new(
                db, ip,
                'Suspicious Activity', 'medium',
                msg,
                window_count=1
            )
    except Exception as e:
        print(f'[SUSPICIOUS ERROR] {e}')


def _rule_wordpress(db, ip):
    """Alert on WordPress brute force."""
    try:
        count = db.execute('''
            SELECT COUNT(*) FROM logs
            WHERE ip_address = ?
            AND source = 'wordpress'
            AND event_type = 'failed_login'
        ''', (ip,)).fetchone()[0]

        if count >= 3:
            _alert_if_new(
                db, ip,
                'WordPress Brute Force', 'high',
                f'{count} failed WordPress login '
                f'attempts from {ip}.',
                window_count=1
            )
    except Exception as e:
        print(f'[WORDPRESS ERROR] {e}')


# ══════════════════════════════════════════════════════════════
#  HELPERS — No time windows, use COUNT instead
# ══════════════════════════════════════════════════════════════

def _alert_if_new(db, ip, alert_type, severity,
                  message, window_count=1):
    """
    Create alert only if fewer than window_count
    alerts of this type already exist for this IP.
    Uses COUNT not time — avoids timestamp issues.
    """
    try:
        existing_count = db.execute('''
            SELECT COUNT(*) FROM alerts
            WHERE ip_address = ?
            AND alert_type   = ?
            AND status       = 'open'
        ''', (ip, alert_type)).fetchone()[0]

        print(f'[DETECTION] Alert check: '
              f'{alert_type} for {ip} — '
              f'{existing_count} existing open alerts')

        if existing_count < window_count:
            _insert(db, ip, alert_type,
                    severity, message)
        else:
            print(f'[DETECTION] Skipped — alert '
                  f'already exists for {ip}')
    except Exception as e:
        print(f'[ALERT CHECK ERROR] {e}')


def _insert(db, ip, alert_type, severity, message):
    """Insert alert row, commit, and send email."""
    try:
        db.execute('''
            INSERT INTO alerts
                (ip_address, alert_type,
                 severity, message)
            VALUES (?, ?, ?, ?)
        ''', (ip, alert_type, severity, message))
        db.commit()

        print(f'✅ [ALERT CREATED] '
              f'[{severity.upper()}] '
              f'{alert_type} — {ip}')

        _send_alert_email(ip, alert_type,
                          severity, message)

    except Exception as e:
        print(f'[INSERT ERROR] {e}')


# ══════════════════════════════════════════════════════════════
#  EMAIL
# ══════════════════════════════════════════════════════════════

EMAIL_ENABLED  = False
EMAIL_SENDER   = 'nsailaridley3@gmail.com'
EMAIL_PASSWORD = 'pbjnozvmrhteldrc'
EMAIL_RECEIVER = 'nsaila.ridley@ictuniversity.edu.cm'
SMTP_HOST      = 'smtp.gmail.com'
SMTP_PORT      = 587


def _send_alert_email(ip, alert_type, severity, message):
    if not EMAIL_ENABLED:
        return

    def _send():
        try:
            now   = datetime.now().strftime(
                '%Y-%m-%d %H:%M:%S')
            color = {
                'high':   '#dc2626',
                'medium': '#d97706',
            }.get(severity, '#2563eb')

            html = f"""
<html><body style="font-family:Arial,sans-serif;
background:#f1f5f9;padding:20px;">
<div style="max-width:520px;margin:0 auto;
background:white;border-radius:12px;overflow:hidden;">
<div style="background:linear-gradient(135deg,
#0a1628,#1e3a8a);padding:22px;text-align:center;">
<h1 style="color:white;margin:0;font-size:18px;">
🛡️ SecureWatch Alert</h1></div>
<div style="background:{color};
padding:12px 18px;">
<h2 style="color:white;margin:0;font-size:14px;">
⚠️ {alert_type} [{severity.upper()}]</h2></div>
<div style="padding:20px;font-size:13px;
color:#374151;">
<p><b>IP Address:</b> {ip}</p>
<p><b>Details:</b> {message}</p>
<p><b>Time:</b> {now}</p></div>
<div style="background:#f8fafc;padding:14px;
text-align:center;border-top:1px solid #e5e7eb;">
<p style="color:#6b7280;font-size:11px;margin:0;">
Log in to SecureWatch to review this alert.</p>
</div></div></body></html>"""

            msg = MIMEMultipart('alternative')
            msg['Subject'] = (
                f'🚨 SecureWatch: {alert_type} '
                f'[{severity.upper()}]'
            )
            msg['From'] = EMAIL_SENDER
            msg['To']   = EMAIL_RECEIVER
            msg.attach(MIMEText(
                f'SecureWatch Alert\n'
                f'Type: {alert_type}\n'
                f'Severity: {severity.upper()}\n'
                f'IP: {ip}\n'
                f'Details: {message}\n'
                f'Time: {now}',
                'plain'
            ))
            msg.attach(MIMEText(html, 'html'))

            with smtplib.SMTP(
                    SMTP_HOST, SMTP_PORT) as server:
                server.ehlo()
                server.starttls()
                server.login(EMAIL_SENDER,
                             EMAIL_PASSWORD)
                server.sendmail(
                    EMAIL_SENDER,
                    EMAIL_RECEIVER,
                    msg.as_string()
                )
            print(f'📧 Email sent: {alert_type}')

        except Exception as e:
            print(f'[EMAIL ERROR] {e}')

    threading.Thread(
        target=_send, daemon=True).start()
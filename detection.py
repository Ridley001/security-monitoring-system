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
        _rule_mass_failed_logins(db)
        db.close()
    except Exception as e:
        print(f'Detection error: {e}')


# ══════════════════════════════════════════════════════════════
#  RULES
# ══════════════════════════════════════════════════════════════

def _rule_brute_force(db, ip):
    """3+ failed logins from SAME IP in 5 minutes."""
    try:
        count = db.execute('''
            SELECT COUNT(*) FROM logs
            WHERE ip_address = ?
            AND event_type = 'failed_login'
            AND timestamp >= datetime('now','-5 minutes')
        ''', (ip,)).fetchone()[0]

        if count >= 3:
            _alert_if_new(
                db, ip,
                'Brute Force Attack', 'high',
                f'{count} failed login attempts from '
                f'{ip} in 5 minutes.',
                window=10
            )
    except Exception as e:
        print(f'Brute force rule error: {e}')


def _rule_mass_failed_logins(db):
    """
    10+ failed logins across ANY IPs in 2 minutes.
    Catches distributed attacks from uploaded logs.
    """
    try:
        count = db.execute('''
            SELECT COUNT(*) FROM logs
            WHERE event_type = 'failed_login'
            AND timestamp >= datetime('now','-2 minutes')
        ''').fetchone()[0]

        if count >= 10:
            # Get the most common attacking IP
            row = db.execute('''
                SELECT ip_address, COUNT(*) as cnt
                FROM logs
                WHERE event_type = 'failed_login'
                AND timestamp >= datetime('now',
                                         '-2 minutes')
                GROUP BY ip_address
                ORDER BY cnt DESC LIMIT 1
            ''').fetchone()

            ip  = row['ip_address'] if row else 'multiple'

            _alert_if_new(
                db, ip,
                'Mass Login Attack', 'high',
                f'{count} failed logins across multiple '
                f'IPs in 2 minutes — possible '
                f'distributed attack.',
                window=5
            )
    except Exception as e:
        print(f'Mass login rule error: {e}')


def _rule_blocked_ip(db, ip):
    """Alert when a blocked IP tries to access system."""
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
                f'Blocked IP {ip} is still attempting '
                f'to access the system.',
                window=10
            )
    except Exception as e:
        print(f'Blocked IP rule error: {e}')


def _rule_suspicious(db, ip, event_type):
    """Alert on suspicious activity events."""
    try:
        if event_type != 'suspicious_activity':
            return

        row = db.execute('''
            SELECT message FROM logs
            WHERE ip_address = ?
            AND event_type = 'suspicious_activity'
            ORDER BY timestamp DESC LIMIT 1
        ''', (ip,)).fetchone()

        msg = row['message'] if row else \
              f'Suspicious activity from {ip}'

        if msg and 'LARGE TRANSFER' in msg.upper():
            # Every large transfer = new alert, no dedup
            _alert_always(
                db, ip,
                'Large Transfer Alert', 'high',
                msg
            )
        else:
            _alert_if_new(
                db, ip,
                'Suspicious Activity', 'medium',
                msg,
                window=3
            )
    except Exception as e:
        print(f'Suspicious rule error: {e}')


def _rule_wordpress(db, ip):
    """Alert on WordPress brute force attempts."""
    try:
        count = db.execute('''
            SELECT COUNT(*) FROM logs
            WHERE ip_address = ?
            AND source = 'wordpress'
            AND event_type = 'failed_login'
            AND timestamp >= datetime('now','-5 minutes')
        ''', (ip,)).fetchone()[0]

        if count >= 3:
            _alert_if_new(
                db, ip,
                'WordPress Brute Force', 'high',
                f'{count} failed WordPress login '
                f'attempts from {ip}.',
                window=5
            )
    except Exception as e:
        print(f'WordPress rule error: {e}')


# ══════════════════════════════════════════════════════════════
#  ALERT HELPERS
# ══════════════════════════════════════════════════════════════

def _alert_if_new(db, ip, alert_type, severity,
                  message, window=5):
    """Create alert only if none in last N minutes."""
    try:
        existing = db.execute('''
            SELECT id FROM alerts
            WHERE ip_address = ?
            AND alert_type = ?
            AND timestamp >= datetime('now',
                             ? || ' minutes')
        ''', (ip, alert_type, f'-{window}')).fetchone()

        if not existing:
            _insert(db, ip, alert_type,
                    severity, message)
    except Exception as e:
        print(f'Alert check error: {e}')


def _alert_always(db, ip, alert_type,
                  severity, message):
    """Always create alert — no dedup."""
    try:
        _insert(db, ip, alert_type, severity, message)
    except Exception as e:
        print(f'Alert always error: {e}')


def _insert(db, ip, alert_type, severity, message):
    """Insert alert row and fire email."""
    try:
        db.execute('''
            INSERT INTO alerts
                (ip_address, alert_type,
                 severity, message)
            VALUES (?, ?, ?, ?)
        ''', (ip, alert_type, severity, message))
        db.commit()
        print(f'🚨 ALERT CREATED: [{severity.upper()}] '
              f'{alert_type} from {ip}')
        _send_alert_email(ip, alert_type,
                          severity, message)
    except Exception as e:
        print(f'Alert insert error: {e}')


# ══════════════════════════════════════════════════════════════
#  EMAIL
# ══════════════════════════════════════════════════════════════

EMAIL_ENABLED  = False
EMAIL_SENDER   = 'nsailaridley3@gmail.com'
EMAIL_PASSWORD = 'pbjnozvm rhteldrc'
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
            color = {'high': '#dc2626',
                     'medium': '#d97706'}.get(
                severity, '#2563eb')

            html = f"""<html><body style="font-family:
Arial,sans-serif;background:#f1f5f9;padding:20px;">
<div style="max-width:520px;margin:0 auto;background:
white;border-radius:12px;overflow:hidden;">
<div style="background:linear-gradient(135deg,
#0a1628,#1e3a8a);padding:22px;text-align:center;">
<h1 style="color:white;margin:0;font-size:18px;">
🛡️ SecureWatch Alert</h1></div>
<div style="background:{color};padding:12px 18px;">
<h2 style="color:white;margin:0;font-size:14px;">
⚠️ {alert_type} [{severity.upper()}]</h2></div>
<div style="padding:20px;font-size:13px;">
<p><b>IP:</b> {ip}</p>
<p><b>Details:</b> {message}</p>
<p><b>Time:</b> {now}</p></div>
<div style="background:#f8fafc;padding:14px;
text-align:center;border-top:1px solid #e5e7eb;">
<p style="color:#6b7280;font-size:11px;margin:0;">
Log in to SecureWatch to review.</p></div>
</div></body></html>"""

            msg            = MIMEMultipart('alternative')
            msg['Subject'] = (f'🚨 SecureWatch: '
                              f'{alert_type} '
                              f'[{severity.upper()}]')
            msg['From']    = EMAIL_SENDER
            msg['To']      = EMAIL_RECEIVER
            msg.attach(MIMEText(
                f'Alert: {alert_type}\n'
                f'IP: {ip}\nDetails: {message}\n'
                f'Time: {now}', 'plain'))
            msg.attach(MIMEText(html, 'html'))

            with smtplib.SMTP(SMTP_HOST,
                              SMTP_PORT) as s:
                s.ehlo()
                s.starttls()
                s.login(EMAIL_SENDER, EMAIL_PASSWORD)
                s.sendmail(EMAIL_SENDER,
                           EMAIL_RECEIVER,
                           msg.as_string())
            print(f'📧 Email sent: {alert_type}')
        except Exception as e:
            print(f'Email error: {e}')

    threading.Thread(target=_send, daemon=True).start()
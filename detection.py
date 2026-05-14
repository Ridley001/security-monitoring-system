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
        print(f'Detection error: {e}')


# ══════════════════════════════════════════════════════════════
#  RULES
# ══════════════════════════════════════════════════════════════

def _rule_brute_force(db, ip):
    try:
        count = db.execute('''
            SELECT COUNT(*) FROM logs
            WHERE ip_address = ?
            AND event_type = 'failed_login'
            AND timestamp >= datetime('now','-60 seconds')
        ''', (ip,)).fetchone()[0]

        if count >= 5:
            _alert_if_new(
                db, ip,
                'Brute Force Attack', 'high',
                f'{count} failed login attempts from '
                f'{ip} in 60 seconds.',
                window=5
            )
    except Exception as e:
        print(f'Brute force rule error: {e}')


def _rule_blocked_ip(db, ip):
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
    try:
        count = db.execute('''
            SELECT COUNT(*) FROM logs
            WHERE ip_address = ?
            AND source = 'wordpress'
            AND event_type = 'failed_login'
            AND timestamp >= datetime('now','-60 seconds')
        ''', (ip,)).fetchone()[0]

        if count >= 3:
            _alert_if_new(
                db, ip,
                'WordPress Brute Force', 'high',
                f'{count} failed WordPress login attempts '
                f'from {ip}.',
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
    """Insert alert and send email notification."""
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

        # Send email in background
        _send_alert_email(ip, alert_type,
                          severity, message)

    except Exception as e:
        print(f'Alert insert error: {e}')


# ══════════════════════════════════════════════════════════════
#  EMAIL — self-contained, no imports from app.py
# ══════════════════════════════════════════════════════════════

# ── Fill in your Gmail credentials here ──────────────────────
EMAIL_ENABLED  = False        # Set True to enable emails
EMAIL_SENDER   = 'nsailaridley3@gmail.com'
EMAIL_PASSWORD = 'p b j n o z v m r h t e l r d c'
EMAIL_RECEIVER = 'nsaila.ridley@ictuniversity.edu.cm'
SMTP_HOST      = 'smtp.gmail.com'
SMTP_PORT      = 587


def _send_alert_email(ip, alert_type, severity, message):
    """Send email alert in background thread."""
    if not EMAIL_ENABLED:
        return

    def _send():
        try:
            now = datetime.now().strftime(
                '%Y-%m-%d %H:%M:%S')

            color = {
                'high':   '#dc2626',
                'medium': '#d97706',
                'low':    '#2563eb',
            }.get(severity, '#2563eb')

            html = f"""
<html><body style="font-family:Arial,sans-serif;
                   background:#f1f5f9;padding:20px;">
<div style="max-width:560px;margin:0 auto;
            background:white;border-radius:12px;
            overflow:hidden;
            box-shadow:0 4px 20px rgba(0,0,0,0.08);">

  <div style="background:linear-gradient(135deg,
              #0a1628,#1e3a8a);
              padding:24px;text-align:center;">
    <h1 style="color:white;margin:0;font-size:20px;">
        🛡️ SecureWatch Alert
    </h1>
  </div>

  <div style="background:{color};padding:14px 20px;">
    <h2 style="color:white;margin:0;font-size:15px;">
        ⚠️ {alert_type} Detected
        [{severity.upper()}]
    </h2>
  </div>

  <div style="padding:24px;">
    <table style="width:100%;border-collapse:collapse;
                  font-size:13px;">
      <tr style="border-bottom:1px solid #f3f4f6;">
        <td style="padding:10px;color:#6b7280;
                   font-weight:600;">Alert Type</td>
        <td style="padding:10px;color:#111827;
                   font-weight:600;">{alert_type}</td>
      </tr>
      <tr style="border-bottom:1px solid #f3f4f6;">
        <td style="padding:10px;color:#6b7280;
                   font-weight:600;">IP Address</td>
        <td style="padding:10px;color:#111827;
                   font-family:monospace;">{ip}</td>
      </tr>
      <tr style="border-bottom:1px solid #f3f4f6;">
        <td style="padding:10px;color:#6b7280;
                   font-weight:600;">Severity</td>
        <td style="padding:10px;color:{color};
                   font-weight:700;">
            {severity.upper()}
        </td>
      </tr>
      <tr style="border-bottom:1px solid #f3f4f6;">
        <td style="padding:10px;color:#6b7280;
                   font-weight:600;">Details</td>
        <td style="padding:10px;color:#374151;">
            {message}
        </td>
      </tr>
      <tr>
        <td style="padding:10px;color:#6b7280;
                   font-weight:600;">Time</td>
        <td style="padding:10px;color:#111827;
                   font-family:monospace;">{now}</td>
      </tr>
    </table>
  </div>

  <div style="background:#f8fafc;padding:18px;
              text-align:center;
              border-top:1px solid #e5e7eb;">
    <p style="color:#6b7280;font-size:12px;margin:0;">
        Log in to SecureWatch to review this alert.
    </p>
  </div>

</div>
</body></html>"""

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

            with smtplib.SMTP(SMTP_HOST,
                               SMTP_PORT) as server:
                server.ehlo()
                server.starttls()
                server.login(EMAIL_SENDER,
                             EMAIL_PASSWORD)
                server.sendmail(
                    EMAIL_SENDER,
                    EMAIL_RECEIVER,
                    msg.as_string()
                )
            print(f'📧 Alert email sent: {alert_type}')

        except Exception as e:
            print(f'Email send error: {e}')

    t = threading.Thread(target=_send, daemon=True)
    t.start()
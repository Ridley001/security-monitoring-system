from flask import (Flask, render_template, redirect,
                   url_for, session, request, flash, jsonify)
from database import init_db, get_db
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from detection import run_detection
import functools
import json

# ── CREATE FLASK APP ─────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = 'security_system_secret_key_2024'
app.permanent_session_lifetime = timedelta(minutes=30)

# ── INITIALIZE DATABASE ──────────────────────────────────────────
with app.app_context():
    init_db()

# ═══════════════════════════════════════════════════════════════
#  DECORATORS & HELPERS
# ═══════════════════════════════════════════════════════════════

def login_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def log_login_attempt(ip_address, username, success):
    db = get_db()
    db.execute('''
        INSERT INTO login_attempts (ip_address, username, success)
        VALUES (?, ?, ?)
    ''', (ip_address, username, 1 if success else 0))
    db.commit()
    db.close()

def is_brute_force(ip_address):
    db = get_db()
    result = db.execute('''
        SELECT COUNT(*) FROM login_attempts
        WHERE ip_address = ?
        AND success = 0
        AND timestamp >= datetime('now', '-60 seconds')
    ''', (ip_address,)).fetchone()[0]
    db.close()
    return result >= 5

# ═══════════════════════════════════════════════════════════════
#  AUTHENTICATION ROUTES
# ═══════════════════════════════════════════════════════════════

@app.route('/')
def index():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET'])
def login():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_post():
    username   = request.form.get('username', '').strip()
    password   = request.form.get('password', '').strip()
    ip_address = request.remote_addr

    if is_brute_force(ip_address):
        flash('Too many failed attempts. Please wait 60 seconds.', 'danger')
        return redirect(url_for('login'))

    db   = get_db()
    user = db.execute(
        'SELECT * FROM users WHERE username = ?', (username,)
    ).fetchone()
    db.close()

    if user and check_password_hash(user['password'], password):
        log_login_attempt(ip_address, username, success=True)
        session.permanent = True
        session['user']   = username
        session['role']   = user['role']
        flash(f'Welcome back, {username}!', 'success')
        return redirect(url_for('dashboard'))
    else:
        log_login_attempt(ip_address, username, success=False)
        flash('Invalid username or password.', 'danger')
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))

# ═══════════════════════════════════════════════════════════════
#  MAIN DASHBOARD
# ═══════════════════════════════════════════════════════════════

@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()

    total_logs     = db.execute('SELECT COUNT(*) FROM logs').fetchone()[0]
    total_alerts   = db.execute(
        'SELECT COUNT(*) FROM alerts WHERE status = "open"').fetchone()[0]
    total_blocked  = db.execute(
        'SELECT COUNT(*) FROM blocked_ips').fetchone()[0]
    total_resolved = db.execute(
        'SELECT COUNT(*) FROM alerts WHERE status = "resolved"').fetchone()[0]
    alert_count    = total_alerts

    recent_logs   = db.execute(
        'SELECT * FROM logs ORDER BY timestamp DESC LIMIT 5').fetchall()
    recent_alerts = db.execute(
        'SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 5').fetchall()

    chart_labels  = []
    chart_success = []
    chart_failed  = []

    for i in range(6, -1, -1):
        day = db.execute('''
            SELECT strftime('%m/%d', datetime('now', '-' || ? || ' days'))
        ''', (i,)).fetchone()[0]
        chart_labels.append(day)

        success = db.execute('''
            SELECT COUNT(*) FROM login_attempts
            WHERE success = 1
            AND date(timestamp) = date('now', '-' || ? || ' days')
        ''', (i,)).fetchone()[0]

        failed = db.execute('''
            SELECT COUNT(*) FROM login_attempts
            WHERE success = 0
            AND date(timestamp) = date('now', '-' || ? || ' days')
        ''', (i,)).fetchone()[0]

        chart_success.append(success)
        chart_failed.append(failed)

    alert_type_rows = db.execute('''
        SELECT alert_type, COUNT(*) as cnt
        FROM alerts GROUP BY alert_type
    ''').fetchall()

    alert_types  = [r['alert_type'] for r in alert_type_rows] or ['No Alerts']
    alert_counts = [r['cnt']        for r in alert_type_rows] or [1]

    db.close()

    return render_template('dashboard.html',
                           total_logs=total_logs,
                           total_alerts=total_alerts,
                           total_blocked=total_blocked,
                           total_resolved=total_resolved,
                           alert_count=alert_count,
                           recent_logs=recent_logs,
                           recent_alerts=recent_alerts,
                           chart_labels=chart_labels,
                           chart_success=chart_success,
                           chart_failed=chart_failed,
                           alert_types=alert_types,
                           alert_counts=alert_counts)

# ═══════════════════════════════════════════════════════════════
#  ALERTS
# ═══════════════════════════════════════════════════════════════

@app.route('/alerts')
@login_required
def alerts():
    db = get_db()
    all_alerts  = db.execute(
        'SELECT * FROM alerts ORDER BY timestamp DESC').fetchall()
    alert_count = db.execute(
        'SELECT COUNT(*) FROM alerts WHERE status = "open"').fetchone()[0]
    db.close()
    return render_template('alerts.html',
                           alerts=all_alerts,
                           alert_count=alert_count)


# ── RESOLVE ALERT ────────────────────────────────────────────────
@app.route('/resolve-alert/<int:alert_id>', methods=['POST'])
@login_required
def resolve_alert(alert_id):
    """Mark an alert as resolved."""
    db = get_db()
    db.execute('''
        UPDATE alerts SET status = 'resolved'
        WHERE id = ?
    ''', (alert_id,))
    db.commit()
    db.close()
    flash('✅ Alert marked as resolved.', 'success')
    return redirect(url_for('alerts'))


# ── API: GET LATEST ALERT COUNT (for real-time notification) ─────
@app.route('/api/alert-count')
@login_required
def api_alert_count():
    """
    Returns the current open alert count as JSON.
    Called every 10 seconds by the browser to check for new alerts.
    """
    db = get_db()
    count = db.execute(
        'SELECT COUNT(*) FROM alerts WHERE status = "open"'
    ).fetchone()[0]

    # Get the most recent open alert for the popup message
    latest = db.execute('''
        SELECT alert_type, ip_address, severity
        FROM alerts
        WHERE status = 'open'
        ORDER BY timestamp DESC
        LIMIT 1
    ''').fetchone()

    db.close()

    return jsonify({
        'count':      count,
        'alert_type': latest['alert_type'] if latest else None,
        'ip_address': latest['ip_address'] if latest else None,
        'severity':   latest['severity']   if latest else None,
    })

# ═══════════════════════════════════════════════════════════════
#  LOGS
# ═══════════════════════════════════════════════════════════════

@app.route('/logs')
@login_required
def logs():
    db = get_db()

    search     = request.args.get('search', '').strip()
    event_type = request.args.get('event_type', '').strip()
    date_from  = request.args.get('date_from', '').strip()

    query  = 'SELECT * FROM logs WHERE 1=1'
    params = []

    if search:
        query += '''
            AND (ip_address LIKE ?
            OR   message    LIKE ?
            OR   source     LIKE ?)
        '''
        params.extend([f'%{search}%', f'%{search}%', f'%{search}%'])

    if event_type:
        query += ' AND event_type = ?'
        params.append(event_type)

    if date_from:
        query += ' AND date(timestamp) >= ?'
        params.append(date_from)

    query += ' ORDER BY timestamp DESC'

    all_logs = db.execute(query, params).fetchall()

    total_logs       = db.execute(
        'SELECT COUNT(*) FROM logs').fetchone()[0]
    failed_count     = db.execute(
        'SELECT COUNT(*) FROM logs '
        'WHERE event_type = "failed_login"').fetchone()[0]
    success_count    = db.execute(
        'SELECT COUNT(*) FROM logs '
        'WHERE event_type = "successful_login"').fetchone()[0]
    suspicious_count = db.execute(
        'SELECT COUNT(*) FROM logs '
        'WHERE event_type = "suspicious_activity"').fetchone()[0]

    event_types = db.execute(
        'SELECT DISTINCT event_type FROM logs ORDER BY event_type'
    ).fetchall()

    alert_count = db.execute(
        'SELECT COUNT(*) FROM alerts WHERE status = "open"'
    ).fetchone()[0]

    blocked_ip_list = [
        row['ip_address'] for row in
        db.execute('SELECT ip_address FROM blocked_ips').fetchall()
    ]

    db.close()

    return render_template('logs.html',
                           logs=all_logs,
                           total_logs=total_logs,
                           failed_count=failed_count,
                           success_count=success_count,
                           suspicious_count=suspicious_count,
                           event_types=event_types,
                           alert_count=alert_count,
                           search=search,
                           event_type=event_type,
                           date_from=date_from,
                           blocked_ip_list=blocked_ip_list)


# ── UPLOAD LOG FILE ──────────────────────────────────────────────
@app.route('/upload-logs', methods=['POST'])
@login_required
def upload_logs():
    if 'logfile' not in request.files:
        flash('No file selected.', 'danger')
        return redirect(url_for('logs'))

    file = request.files['logfile']

    if file.filename == '':
        flash('No file selected.', 'danger')
        return redirect(url_for('logs'))

    if not file.filename.endswith('.json'):
        flash('Please upload a .json file only.', 'danger')
        return redirect(url_for('logs'))

    try:
        data = json.load(file)

        if not isinstance(data, list):
            flash('JSON file must contain a list of log entries.', 'danger')
            return redirect(url_for('logs'))

        db     = get_db()
        count  = 0
        errors = 0

        for entry in data:
            try:
                ip    = entry.get('ip_address', '0.0.0.0')
                event = entry.get('event_type', 'unknown')

                db.execute('''
                    INSERT INTO logs (ip_address, event_type, message, source)
                    VALUES (?, ?, ?, ?)
                ''', (
                    ip,
                    event,
                    entry.get('message', ''),
                    entry.get('source',  'uploaded'),
                ))
                count += 1

                # ── Run detection engine on every log ────────────
                run_detection(ip, event)

            except Exception:
                errors += 1

        db.commit()
        db.close()

        if errors:
            flash(
                f'✅ {count} logs imported. ⚠️ {errors} entries skipped.',
                'warning')
        else:
            flash(
                f'✅ {count} logs imported! Detection engine has analyzed '
                f'all entries.', 'success')

    except Exception as e:
        flash(f'❌ Error reading file: {str(e)}', 'danger')

    return redirect(url_for('logs'))


# ── DELETE SINGLE LOG ────────────────────────────────────────────
@app.route('/delete-log/<int:log_id>', methods=['POST'])
@login_required
def delete_log(log_id):
    db = get_db()
    db.execute('DELETE FROM logs WHERE id = ?', (log_id,))
    db.commit()
    db.close()
    flash('🗑️ Log entry deleted.', 'success')
    return redirect(url_for('logs'))


# ── DELETE ALL LOGS ──────────────────────────────────────────────
@app.route('/delete-all-logs', methods=['POST'])
@login_required
def delete_all_logs():
    db = get_db()
    db.execute('DELETE FROM logs')
    db.commit()
    db.close()
    flash('🗑️ All logs have been cleared.', 'success')
    return redirect(url_for('logs'))


# ── BLOCK IP FROM LOGS PAGE ──────────────────────────────────────
@app.route('/block-ip-from-log', methods=['POST'])
@login_required
def block_ip_from_log():
    ip_address = request.form.get('ip_address', '').strip()
    reason     = request.form.get('reason',
                                  'Blocked from logs page').strip()

    if not ip_address:
        flash('No IP address provided.', 'danger')
        return redirect(url_for('logs'))

    db = get_db()

    already = db.execute(
        'SELECT id FROM blocked_ips WHERE ip_address = ?',
        (ip_address,)
    ).fetchone()

    if already:
        flash(f'⚠️ {ip_address} is already blocked.', 'warning')
    else:
        db.execute(
            'INSERT INTO blocked_ips (ip_address, reason) VALUES (?, ?)',
            (ip_address, reason)
        )
        db.commit()
        flash(f'🚫 {ip_address} has been blocked successfully!', 'success')

    db.close()
    return redirect(url_for('logs'))

# ═══════════════════════════════════════════════════════════════
#  BLOCKED IPs
# ═══════════════════════════════════════════════════════════════

@app.route('/blocked')
@login_required
def blocked():
    db = get_db()
    blocked_ips = db.execute(
        'SELECT * FROM blocked_ips ORDER BY blocked_at DESC').fetchall()
    alert_count = db.execute(
        'SELECT COUNT(*) FROM alerts WHERE status = "open"').fetchone()[0]
    db.close()
    return render_template('blocked.html',
                           blocked_ips=blocked_ips,
                           alert_count=alert_count)


# ── UNBLOCK IP ───────────────────────────────────────────────────
@app.route('/unblock-ip/<int:ip_id>', methods=['POST'])
@login_required
def unblock_ip(ip_id):
    db = get_db()
    ip_row = db.execute(
        'SELECT ip_address FROM blocked_ips WHERE id = ?',
        (ip_id,)
    ).fetchone()

    if ip_row:
        db.execute('DELETE FROM blocked_ips WHERE id = ?', (ip_id,))
        db.commit()
        flash(f'✅ {ip_row["ip_address"]} has been unblocked.', 'success')
    else:
        flash('IP not found.', 'danger')

    db.close()
    return redirect(url_for('blocked'))

# ═══════════════════════════════════════════════════════════════
#  LIVE MONITOR
# ═══════════════════════════════════════════════════════════════

@app.route('/live-monitor')
@login_required
def live_monitor():
    db = get_db()
    alert_count = db.execute(
        'SELECT COUNT(*) FROM alerts WHERE status = "open"').fetchone()[0]
    db.close()
    return render_template('live_monitor.html',
                           alert_count=alert_count)

# ═══════════════════════════════════════════════════════════════
#  RUN APP
# ═══════════════════════════════════════════════════════════════

if __name__ == '__main__':
    app.run(debug=True, port=5000)
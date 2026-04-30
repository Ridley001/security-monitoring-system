from flask import (Flask, render_template, redirect,
                   url_for, session, request, flash)
from database import init_db, get_db
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import functools

# ── CREATE FLASK APP ─────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = 'security_system_secret_key_2024'

# Session lifetime — auto logout after 30 minutes of inactivity
app.permanent_session_lifetime = timedelta(minutes=30)

# ── INITIALIZE DATABASE ──────────────────────────────────────────
with app.app_context():
    init_db()

# ═══════════════════════════════════════════════════════════════
#  DECORATORS & HELPERS
# ═══════════════════════════════════════════════════════════════

# ── LOGIN REQUIRED DECORATOR ─────────────────────────────────────
def login_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ── HELPER: LOG LOGIN ATTEMPT ────────────────────────────────────
def log_login_attempt(ip_address, username, success):
    """Save every login attempt to the database."""
    db = get_db()
    db.execute('''
        INSERT INTO login_attempts (ip_address, username, success)
        VALUES (?, ?, ?)
    ''', (ip_address, username, 1 if success else 0))
    db.commit()
    db.close()

# ── HELPER: CHECK BRUTE FORCE ────────────────────────────────────
def is_brute_force(ip_address):
    """Check if an IP has failed more than 5 times in the last 60 seconds."""
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

# ── HOME ─────────────────────────────────────────────────────────
@app.route('/')
def index():
    """Redirect to dashboard or login."""
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# ── LOGIN (GET) ──────────────────────────────────────────────────
@app.route('/login', methods=['GET'])
def login():
    """Display the login page."""
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

# ── LOGIN (POST) ─────────────────────────────────────────────────
@app.route('/login', methods=['POST'])
def login_post():
    """Handle login form submission."""
    username   = request.form.get('username', '').strip()
    password   = request.form.get('password', '').strip()
    ip_address = request.remote_addr

    # STEP 1: Check for brute force
    if is_brute_force(ip_address):
        flash('Too many failed attempts. Please wait 60 seconds.', 'danger')
        return redirect(url_for('login'))

    # STEP 2: Find user in database
    db   = get_db()
    user = db.execute(
        'SELECT * FROM users WHERE username = ?', (username,)
    ).fetchone()
    db.close()

    # STEP 3: Check password
    if user and check_password_hash(user['password'], password):
        # ✅ Correct credentials
        log_login_attempt(ip_address, username, success=True)
        session.permanent = True
        session['user']   = username
        session['role']   = user['role']
        flash(f'Welcome back, {username}!', 'success')
        return redirect(url_for('dashboard'))
    else:
        # ❌ Wrong credentials
        log_login_attempt(ip_address, username, success=False)
        flash('Invalid username or password.', 'danger')
        return redirect(url_for('login'))

# ── LOGOUT ───────────────────────────────────────────────────────
@app.route('/logout')
def logout():
    """Clear session and redirect to login."""
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))

# ═══════════════════════════════════════════════════════════════
#  MAIN DASHBOARD
# ═══════════════════════════════════════════════════════════════

@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard page."""
    db = get_db()

    # ── Stat card counts ────────────────────────────────────────
    total_logs     = db.execute(
        'SELECT COUNT(*) FROM logs').fetchone()[0]
    total_alerts   = db.execute(
        'SELECT COUNT(*) FROM alerts WHERE status = "open"').fetchone()[0]
    total_blocked  = db.execute(
        'SELECT COUNT(*) FROM blocked_ips').fetchone()[0]
    total_resolved = db.execute(
        'SELECT COUNT(*) FROM alerts WHERE status = "resolved"').fetchone()[0]
    alert_count    = total_alerts

    # ── Recent data ─────────────────────────────────────────────
    recent_logs   = db.execute(
        'SELECT * FROM logs ORDER BY timestamp DESC LIMIT 5').fetchall()
    recent_alerts = db.execute(
        'SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 5').fetchall()

    # ── Chart 1: Login activity last 7 days ─────────────────────
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

    # ── Chart 2: Alert types ─────────────────────────────────────
    alert_type_rows = db.execute('''
        SELECT alert_type, COUNT(*) as cnt
        FROM alerts
        GROUP BY alert_type
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
    """Alerts page."""
    db = get_db()
    all_alerts  = db.execute(
        'SELECT * FROM alerts ORDER BY timestamp DESC').fetchall()
    alert_count = db.execute(
        'SELECT COUNT(*) FROM alerts WHERE status = "open"').fetchone()[0]
    db.close()
    return render_template('alerts.html',
                           alerts=all_alerts,
                           alert_count=alert_count)

# ═══════════════════════════════════════════════════════════════
#  LOGS
# ═══════════════════════════════════════════════════════════════

@app.route('/logs')
@login_required
def logs():
    """Logs page."""
    db = get_db()
    all_logs    = db.execute(
        'SELECT * FROM logs ORDER BY timestamp DESC').fetchall()
    alert_count = db.execute(
        'SELECT COUNT(*) FROM alerts WHERE status = "open"').fetchone()[0]
    db.close()
    return render_template('logs.html',
                           logs=all_logs,
                           alert_count=alert_count)

# ═══════════════════════════════════════════════════════════════
#  BLOCKED IPs
# ═══════════════════════════════════════════════════════════════

@app.route('/blocked')
@login_required
def blocked():
    """Blocked IPs page."""
    db = get_db()
    blocked_ips = db.execute(
        'SELECT * FROM blocked_ips ORDER BY blocked_at DESC').fetchall()
    alert_count = db.execute(
        'SELECT COUNT(*) FROM alerts WHERE status = "open"').fetchone()[0]
    db.close()
    return render_template('blocked.html',
                           blocked_ips=blocked_ips,
                           alert_count=alert_count)

# ═══════════════════════════════════════════════════════════════
#  LIVE MONITOR
# ═══════════════════════════════════════════════════════════════

@app.route('/live-monitor')
@login_required
def live_monitor():
    """Live monitoring page."""
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
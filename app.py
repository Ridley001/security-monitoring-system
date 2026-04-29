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

# ── LOGIN REQUIRED DECORATOR ─────────────────────────────────────
# We use this to protect pages that need login
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
#  ROUTES
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
    # If already logged in, go straight to dashboard
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

    # ── STEP 1: Check for brute force ───────────────────────────
    if is_brute_force(ip_address):
        flash('Too many failed attempts. Please wait 60 seconds.', 'danger')
        return redirect(url_for('login'))

    # ── STEP 2: Find user in database ───────────────────────────
    db   = get_db()
    user = db.execute(
        'SELECT * FROM users WHERE username = ?', (username,)
    ).fetchone()
    db.close()

    # ── STEP 3: Check password ───────────────────────────────────
    if user and check_password_hash(user['password'], password):
        # ✅ Correct — log success and start session
        log_login_attempt(ip_address, username, success=True)
        session.permanent = True
        session['user']   = username
        session['role']   = user['role']
        flash(f'Welcome back, {username}!', 'success')
        return redirect(url_for('dashboard'))
    else:
        # ❌ Wrong — log failure and show error
        log_login_attempt(ip_address, username, success=False)
        flash('Invalid username or password.', 'danger')
        return redirect(url_for('login'))

# ── DASHBOARD ────────────────────────────────────────────────────
@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard page."""
    db = get_db()

    total_logs    = db.execute('SELECT COUNT(*) FROM logs').fetchone()[0]
    total_alerts  = db.execute(
        'SELECT COUNT(*) FROM alerts WHERE status = "open"').fetchone()[0]
    total_blocked = db.execute('SELECT COUNT(*) FROM blocked_ips').fetchone()[0]
    recent_logs   = db.execute(
        'SELECT * FROM logs ORDER BY timestamp DESC LIMIT 5').fetchall()
    recent_alerts = db.execute(
        'SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 5').fetchall()

    db.close()

    return render_template('dashboard.html',
                           total_logs=total_logs,
                           total_alerts=total_alerts,
                           total_blocked=total_blocked,
                           recent_logs=recent_logs,
                           recent_alerts=recent_alerts)

# ── LOGOUT ───────────────────────────────────────────────────────
@app.route('/logout')
def logout():
    """Clear session and redirect to login."""
    username = session.get('user', 'Unknown')
    session.clear()
    flash(f'You have been logged out successfully.', 'success')
    return redirect(url_for('login'))

# ── RUN APP ──────────────────────────────────────────────────────
if __name__ == '__main__':
    app.run(debug=True, port=5000)
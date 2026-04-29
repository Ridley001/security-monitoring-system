from flask import Flask, render_template, redirect, url_for, session, request, flash
from database import init_db, get_db
from datetime import datetime

# ── CREATE FLASK APP ─────────────────────────────────────────────
app = Flask(__name__)

# Secret key for session handling (keeps login secure)
app.secret_key = 'security_system_secret_key_2024'

# ── INITIALIZE DATABASE ──────────────────────────────────────────
# Creates tables when app starts (if they don't exist)
with app.app_context():
    init_db()

# ── ROUTES ───────────────────────────────────────────────────────

@app.route('/')
def index():
    """Home page — redirects to dashboard or login."""
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/dashboard')
def dashboard():
    """Main dashboard page."""
    # Check if admin is logged in
    if 'user' not in session:
        return redirect(url_for('login'))

    # Get counts from database for dashboard cards
    db = get_db()

    total_logs     = db.execute('SELECT COUNT(*) FROM logs').fetchone()[0]
    total_alerts   = db.execute('SELECT COUNT(*) FROM alerts WHERE status = "open"').fetchone()[0]
    total_blocked  = db.execute('SELECT COUNT(*) FROM blocked_ips').fetchone()[0]
    recent_logs    = db.execute('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 5').fetchall()
    recent_alerts  = db.execute('SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 5').fetchall()

    db.close()

    return render_template('dashboard.html',
                           total_logs=total_logs,
                           total_alerts=total_alerts,
                           total_blocked=total_blocked,
                           recent_logs=recent_logs,
                           recent_alerts=recent_alerts)


@app.route('/login', methods=['GET'])
def login():
    """Login page — just displays the form."""
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def login_post():
    """Handles the login form when submitted."""
    username = request.form.get('username')
    password = request.form.get('password')

    # Check database for matching user
    db = get_db()
    user = db.execute(
        'SELECT * FROM users WHERE username = ? AND password = ?',
        (username, password)
    ).fetchone()
    db.close()

    if user:
        # Correct credentials — save user in session and go to dashboard
        session['user'] = username
        return redirect(url_for('dashboard'))
    else:
        # Wrong credentials — show error message
        flash('Invalid username or password', 'danger')
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    """Log the admin out."""
    session.clear()
    return redirect(url_for('login'))


# ── RUN APP ──────────────────────────────────────────────────────
if __name__ == '__main__':
    app.run(debug=True, port=5000)
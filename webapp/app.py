from flask import (Flask, render_template, request,
                   redirect, url_for, session, flash)
import requests

# ── CREATE WEB APP ───────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = 'webapp_secret_key_2024'

# ── MAIN SYSTEM SETTINGS ─────────────────────────────────────────
MAIN_SYSTEM_URL    = 'http://127.0.0.1:5000/api/logs'
MAIN_BLOCKED_URL   = 'http://127.0.0.1:5000/api/is-blocked'
API_KEY            = 'securewatch-api-key-2024'

# ── FAKE USER DATABASE ───────────────────────────────────────────
USERS = {
    'alice':   'password123',
    'bob':     'letmein456',
    'charlie': 'secret789',
}

# ═══════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════

def send_log(ip_address, event_type, message):
    """Send a log entry to the main security system."""
    try:
        response = requests.post(
            MAIN_SYSTEM_URL,
            json={
                'ip_address': ip_address,
                'event_type': event_type,
                'message':    message,
                'source':     'authorized_webapp',
            },
            headers={
                'X-API-Key':    API_KEY,
                'Content-Type': 'application/json',
            },
            timeout=3
        )
        if response.status_code == 201:
            print(f'✅ Log sent: {event_type} from {ip_address}')
        else:
            print(f'⚠️ Log API returned: {response.status_code}')

    except requests.exceptions.ConnectionError:
        print('⚠️ Main system not reachable — log not sent')
    except Exception as e:
        print(f'⚠️ Log send error: {e}')


def is_ip_blocked(ip_address):
    """
    Ask the main system if this IP is blocked.
    Returns True if blocked, False if not.
    """
    try:
        response = requests.get(
            MAIN_BLOCKED_URL,
            params={'ip': ip_address},
            headers={'X-API-Key': API_KEY},
            timeout=3
        )
        if response.status_code == 200:
            data = response.json()
            return data.get('blocked', False)
    except Exception as e:
        print(f'⚠️ Block check error: {e}')
    # If main system is unreachable, allow access
    return False

# ═══════════════════════════════════════════════════════════════
#  ROUTES
# ═══════════════════════════════════════════════════════════════

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET'])
def login():
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def login_post():
    """
    Handle login:
    1. Check if IP is blocked FIRST
    2. Then check credentials
    3. Log every attempt to main system
    """
    username   = request.form.get('username', '').strip()
    password   = request.form.get('password', '').strip()
    ip_address = request.remote_addr

    # ── STEP 1: Check if IP is blocked BEFORE anything else ──────
    if is_ip_blocked(ip_address):
        # Log the blocked access attempt
        send_log(
            ip_address,
            'blocked_access',
            f'Blocked IP attempted to login as "{username}"'
        )
        # Show access denied page — do NOT log them in
        return render_template('blocked.html',
                               ip_address=ip_address)

    # ── STEP 2: Check credentials ────────────────────────────────
    if username in USERS and USERS[username] == password:
        # ✅ Correct credentials + not blocked = allow in
        session['user'] = username
        send_log(
            ip_address,
            'successful_login',
            f'User "{username}" logged in successfully'
        )
        flash(f'Welcome, {username}!', 'success')
        return redirect(url_for('dashboard'))

    else:
        # ❌ Wrong credentials
        send_log(
            ip_address,
            'failed_login',
            f'Failed login attempt for username: "{username}"'
        )
        flash('Invalid username or password.', 'danger')
        return redirect(url_for('login'))


@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        flash('Please log in first.', 'warning')
        return redirect(url_for('login'))
    return render_template('dashboard.html',
                           user=session['user'])


@app.route('/logout')
def logout():
    username   = session.get('user', 'Unknown')
    ip_address = request.remote_addr
    send_log(
        ip_address,
        'successful_login',
        f'User "{username}" logged out'
    )
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True, port=5001)
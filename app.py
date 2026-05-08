from flask import (Flask, render_template, redirect,
                   url_for, session, request, flash,
                   jsonify, make_response)
from database import init_db, get_db
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from detection import run_detection
import functools
import json
import os

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, cm
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                 Table, TableStyle, HRFlowable)
from reportlab.lib.enums import TA_CENTER
import io

# ── CREATE FLASK APP ─────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = 'security_system_secret_key_2024'
app.permanent_session_lifetime = timedelta(minutes=30)

# Upload folder for transaction documents
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

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

def get_alert_count():
    db = get_db()
    count = db.execute(
        'SELECT COUNT(*) FROM alerts WHERE status = "open"'
    ).fetchone()[0]
    db.close()
    return count

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
    total_blocked  = db.execute('SELECT COUNT(*) FROM blocked_ips').fetchone()[0]
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

        admin_success = db.execute('''
            SELECT COUNT(*) FROM login_attempts WHERE success = 1
            AND date(timestamp) = date('now', '-' || ? || ' days')
        ''', (i,)).fetchone()[0]

        webapp_success = db.execute('''
            SELECT COUNT(*) FROM logs WHERE event_type = 'successful_login'
            AND date(timestamp) = date('now', '-' || ? || ' days')
        ''', (i,)).fetchone()[0]

        admin_failed = db.execute('''
            SELECT COUNT(*) FROM login_attempts WHERE success = 0
            AND date(timestamp) = date('now', '-' || ? || ' days')
        ''', (i,)).fetchone()[0]

        webapp_failed = db.execute('''
            SELECT COUNT(*) FROM logs WHERE event_type = 'failed_login'
            AND date(timestamp) = date('now', '-' || ? || ' days')
        ''', (i,)).fetchone()[0]

        chart_success.append(admin_success + webapp_success)
        chart_failed.append(admin_failed + webapp_failed)

    alert_type_rows = db.execute('''
        SELECT alert_type, COUNT(*) as cnt FROM alerts GROUP BY alert_type
    ''').fetchall()

    alert_types  = [r['alert_type'] for r in alert_type_rows] or ['No Alerts']
    alert_counts = [r['cnt'] for r in alert_type_rows] or [1]

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
    search   = request.args.get('search',   '').strip()
    severity = request.args.get('severity', '').strip()
    status   = request.args.get('status',   '').strip()

    query  = 'SELECT * FROM alerts WHERE 1=1'
    params = []
    if search:
        query += ' AND (ip_address LIKE ? OR alert_type LIKE ?)'
        params.extend([f'%{search}%', f'%{search}%'])
    if severity:
        query += ' AND severity = ?'
        params.append(severity)
    if status:
        query += ' AND status = ?'
        params.append(status)
    query += ' ORDER BY timestamp DESC'

    all_alerts     = db.execute(query, params).fetchall()
    open_count     = db.execute('SELECT COUNT(*) FROM alerts WHERE status = "open"').fetchone()[0]
    resolved_count = db.execute('SELECT COUNT(*) FROM alerts WHERE status = "resolved"').fetchone()[0]
    high_count     = db.execute('SELECT COUNT(*) FROM alerts WHERE severity = "high" AND status = "open"').fetchone()[0]
    total_count    = db.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]
    alert_count    = open_count

    blocked_ip_list = [
        row['ip_address'] for row in
        db.execute('SELECT ip_address FROM blocked_ips').fetchall()
    ]
    db.close()

    return render_template('alerts.html',
                           alerts=all_alerts,
                           open_count=open_count,
                           resolved_count=resolved_count,
                           high_count=high_count,
                           total_count=total_count,
                           alert_count=alert_count,
                           blocked_ip_list=blocked_ip_list,
                           search=search,
                           severity=severity,
                           status=status)

@app.route('/resolve-alert/<int:alert_id>', methods=['POST'])
@login_required
def resolve_alert(alert_id):
    db = get_db()
    db.execute('UPDATE alerts SET status = "resolved" WHERE id = ?', (alert_id,))
    db.commit()
    db.close()
    flash('✅ Alert marked as resolved.', 'success')
    return redirect(url_for('alerts'))

@app.route('/delete-alert/<int:alert_id>', methods=['POST'])
@login_required
def delete_alert(alert_id):
    db = get_db()
    db.execute('DELETE FROM alerts WHERE id = ?', (alert_id,))
    db.commit()
    db.close()
    flash('🗑️ Alert deleted.', 'success')
    return redirect(url_for('alerts'))

@app.route('/clear-resolved-alerts', methods=['POST'])
@login_required
def clear_resolved_alerts():
    db = get_db()
    db.execute('DELETE FROM alerts WHERE status = "resolved"')
    db.commit()
    db.close()
    flash('🗑️ All resolved alerts cleared.', 'success')
    return redirect(url_for('alerts'))

@app.route('/block-ip-from-alert', methods=['POST'])
@login_required
def block_ip_from_alert():
    ip_address = request.form.get('ip_address', '').strip()
    reason     = request.form.get('reason', 'Blocked from alerts page').strip()
    if not ip_address:
        flash('No IP address provided.', 'danger')
        return redirect(url_for('alerts'))
    db = get_db()
    already = db.execute('SELECT id FROM blocked_ips WHERE ip_address = ?', (ip_address,)).fetchone()
    if already:
        flash(f'⚠️ {ip_address} is already blocked.', 'warning')
    else:
        db.execute('INSERT INTO blocked_ips (ip_address, reason) VALUES (?, ?)', (ip_address, reason))
        db.commit()
        flash(f'🚫 {ip_address} has been blocked!', 'success')
    db.close()
    return redirect(url_for('alerts'))

@app.route('/api/alert-count')
@login_required
def api_alert_count():
    db    = get_db()
    count = db.execute('SELECT COUNT(*) FROM alerts WHERE status = "open"').fetchone()[0]
    latest = db.execute('''
        SELECT alert_type, ip_address, severity FROM alerts
        WHERE status = 'open' ORDER BY timestamp DESC LIMIT 1
    ''').fetchone()
    db.close()
    return jsonify({
        'count':      count,
        'alert_type': latest['alert_type'] if latest else None,
        'ip_address': latest['ip_address'] if latest else None,
        'severity':   latest['severity']   if latest else None,
    })

@app.route('/api/is-blocked')
def api_is_blocked():
    api_key = request.headers.get('X-API-Key', '')
    if api_key != 'securewatch-api-key-2024':
        return jsonify({'error': 'Unauthorized'}), 401
    ip = request.args.get('ip', '').strip()
    if not ip:
        return jsonify({'error': 'No IP provided'}), 400
    db      = get_db()
    blocked = db.execute('SELECT id FROM blocked_ips WHERE ip_address = ?', (ip,)).fetchone()
    db.close()
    return jsonify({'ip': ip, 'blocked': blocked is not None})

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
        query += ' AND (ip_address LIKE ? OR message LIKE ? OR source LIKE ?)'
        params.extend([f'%{search}%', f'%{search}%', f'%{search}%'])
    if event_type:
        query += ' AND event_type = ?'
        params.append(event_type)
    if date_from:
        query += ' AND date(timestamp) >= ?'
        params.append(date_from)
    query += ' ORDER BY timestamp DESC'

    all_logs         = db.execute(query, params).fetchall()
    total_logs       = db.execute('SELECT COUNT(*) FROM logs').fetchone()[0]
    failed_count     = db.execute('SELECT COUNT(*) FROM logs WHERE event_type = "failed_login"').fetchone()[0]
    success_count    = db.execute('SELECT COUNT(*) FROM logs WHERE event_type = "successful_login"').fetchone()[0]
    suspicious_count = db.execute('SELECT COUNT(*) FROM logs WHERE event_type = "suspicious_activity"').fetchone()[0]
    event_types      = db.execute('SELECT DISTINCT event_type FROM logs ORDER BY event_type').fetchall()
    alert_count      = db.execute('SELECT COUNT(*) FROM alerts WHERE status = "open"').fetchone()[0]
    blocked_ip_list  = [row['ip_address'] for row in db.execute('SELECT ip_address FROM blocked_ips').fetchall()]
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
        db = get_db()
        count = 0; errors = 0; inserted = []
        for entry in data:
            try:
                ip    = str(entry.get('ip_address', '0.0.0.0')).strip()
                event = str(entry.get('event_type', 'unknown')).strip()
                msg   = str(entry.get('message', '')).strip()
                src   = str(entry.get('source', 'uploaded')).strip()
                db.execute('INSERT INTO logs (ip_address, event_type, message, source) VALUES (?, ?, ?, ?)',
                           (ip, event, msg, src))
                inserted.append((ip, event))
                count += 1
            except Exception as e:
                errors += 1
        db.commit()
        db.close()
        for ip, event in list(set(inserted)):
            try:
                run_detection(ip, event)
            except Exception:
                pass
        db2 = get_db()
        new_alert_count = db2.execute('SELECT COUNT(*) FROM alerts WHERE status = "open"').fetchone()[0]
        db2.close()
        flash(f'✅ {count} logs imported! 🚨 {new_alert_count} open alert(s) detected.', 'success' if not errors else 'warning')
    except Exception as e:
        flash(f'❌ Error reading file: {str(e)}', 'danger')
    return redirect(url_for('logs'))

@app.route('/delete-log/<int:log_id>', methods=['POST'])
@login_required
def delete_log(log_id):
    db = get_db()
    db.execute('DELETE FROM logs WHERE id = ?', (log_id,))
    db.commit()
    db.close()
    flash('🗑️ Log entry deleted.', 'success')
    return redirect(url_for('logs'))

@app.route('/delete-all-logs', methods=['POST'])
@login_required
def delete_all_logs():
    db = get_db()
    db.execute('DELETE FROM logs')
    db.commit()
    db.close()
    flash('🗑️ All logs have been cleared.', 'success')
    return redirect(url_for('logs'))

@app.route('/block-ip-from-log', methods=['POST'])
@login_required
def block_ip_from_log():
    ip_address = request.form.get('ip_address', '').strip()
    reason     = request.form.get('reason', 'Blocked from logs page').strip()
    if not ip_address:
        flash('No IP address provided.', 'danger')
        return redirect(url_for('logs'))
    db      = get_db()
    already = db.execute('SELECT id FROM blocked_ips WHERE ip_address = ?', (ip_address,)).fetchone()
    if already:
        flash(f'⚠️ {ip_address} is already blocked.', 'warning')
    else:
        db.execute('INSERT INTO blocked_ips (ip_address, reason) VALUES (?, ?)', (ip_address, reason))
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
    db     = get_db()
    search = request.args.get('search', '').strip()
    if search:
        blocked_ips = db.execute('''
            SELECT * FROM blocked_ips WHERE ip_address LIKE ? OR reason LIKE ?
            ORDER BY blocked_at DESC
        ''', (f'%{search}%', f'%{search}%')).fetchall()
    else:
        blocked_ips = db.execute('SELECT * FROM blocked_ips ORDER BY blocked_at DESC').fetchall()
    total_blocked = db.execute('SELECT COUNT(*) FROM blocked_ips').fetchone()[0]
    alert_count   = db.execute('SELECT COUNT(*) FROM alerts WHERE status = "open"').fetchone()[0]
    db.close()
    return render_template('blocked.html', blocked_ips=blocked_ips,
                           total_blocked=total_blocked, alert_count=alert_count, search=search)

@app.route('/unblock-ip/<int:ip_id>', methods=['POST'])
@login_required
def unblock_ip(ip_id):
    db     = get_db()
    ip_row = db.execute('SELECT ip_address FROM blocked_ips WHERE id = ?', (ip_id,)).fetchone()
    if ip_row:
        db.execute('DELETE FROM blocked_ips WHERE id = ?', (ip_id,))
        db.commit()
        flash(f'✅ {ip_row["ip_address"]} has been unblocked.', 'success')
    else:
        flash('IP not found.', 'danger')
    db.close()
    return redirect(url_for('blocked'))

@app.route('/manual-block', methods=['POST'])
@login_required
def manual_block():
    ip_address = request.form.get('ip_address', '').strip()
    reason     = request.form.get('reason', 'Manually blocked by admin').strip()
    if not ip_address:
        flash('Please enter an IP address.', 'danger')
        return redirect(url_for('blocked'))
    parts = ip_address.split('.')
    if len(parts) != 4:
        flash(f'❌ Invalid IP address format: {ip_address}', 'danger')
        return redirect(url_for('blocked'))
    db      = get_db()
    already = db.execute('SELECT id FROM blocked_ips WHERE ip_address = ?', (ip_address,)).fetchone()
    if already:
        flash(f'⚠️ {ip_address} is already blocked.', 'warning')
    else:
        db.execute('INSERT INTO blocked_ips (ip_address, reason) VALUES (?, ?)', (ip_address, reason))
        db.commit()
        flash(f'🚫 {ip_address} has been manually blocked!', 'success')
    db.close()
    return redirect(url_for('blocked'))

@app.route('/view-ip-logs/<ip_address>')
@login_required
def view_ip_logs(ip_address):
    return redirect(url_for('logs', search=ip_address))

# ═══════════════════════════════════════════════════════════════
#  LIVE MONITOR
# ═══════════════════════════════════════════════════════════════

@app.route('/live-monitor')
@login_required
def live_monitor():
    db = get_db()
    alert_count   = db.execute('SELECT COUNT(*) FROM alerts WHERE status = "open"').fetchone()[0]
    today_events  = db.execute('SELECT COUNT(*) FROM logs WHERE date(timestamp) = date("now")').fetchone()[0]
    today_threats = db.execute('SELECT COUNT(*) FROM alerts WHERE date(timestamp) = date("now") AND status = "open"').fetchone()[0]
    total_blocked = db.execute('SELECT COUNT(*) FROM blocked_ips').fetchone()[0]
    sources       = db.execute('SELECT DISTINCT source FROM logs WHERE source IS NOT NULL ORDER BY source').fetchall()
    db.close()
    return render_template('live_monitor.html',
                           alert_count=alert_count,
                           today_events=today_events,
                           today_threats=today_threats,
                           total_blocked=total_blocked,
                           sources=sources)

@app.route('/api/live-logs')
@login_required
def api_live_logs():
    source = request.args.get('source', '').strip()
    since  = request.args.get('since',  '').strip()
    query  = 'SELECT * FROM logs WHERE 1=1'
    params = []
    if source:
        query += ' AND source = ?'
        params.append(source)
    if since:
        query += ' AND id > ?'
        params.append(since)
    query += ' ORDER BY timestamp DESC LIMIT 50'
    db   = get_db()
    rows = db.execute(query, params).fetchall()
    alerts = db.execute('SELECT * FROM alerts WHERE status = "open" ORDER BY timestamp DESC LIMIT 5').fetchall()
    today_events  = db.execute('SELECT COUNT(*) FROM logs WHERE date(timestamp) = date("now")').fetchone()[0]
    today_threats = db.execute('SELECT COUNT(*) FROM alerts WHERE date(timestamp) = date("now") AND status = "open"').fetchone()[0]
    db.close()
    return jsonify({
        'logs':          [{'id': r['id'], 'ip_address': r['ip_address'], 'event_type': r['event_type'],
                           'message': r['message'] or '', 'source': r['source'] or 'unknown', 'timestamp': r['timestamp']} for r in rows],
        'alerts':        [{'id': a['id'], 'ip_address': a['ip_address'], 'alert_type': a['alert_type'],
                           'severity': a['severity'], 'timestamp': a['timestamp']} for a in alerts],
        'today_events':  today_events,
        'today_threats': today_threats,
    })

@app.route('/api/live-stats')
@login_required
def api_live_stats():
    db = get_db()
    today_events  = db.execute('SELECT COUNT(*) FROM logs WHERE date(timestamp) = date("now")').fetchone()[0]
    today_threats = db.execute('SELECT COUNT(*) FROM alerts WHERE date(timestamp) = date("now") AND status = "open"').fetchone()[0]
    total_blocked = db.execute('SELECT COUNT(*) FROM blocked_ips').fetchone()[0]
    latest_log    = db.execute('SELECT timestamp FROM logs ORDER BY timestamp DESC LIMIT 1').fetchone()
    db.close()
    return jsonify({
        'today_events':  today_events,
        'today_threats': today_threats,
        'total_blocked': total_blocked,
        'last_activity': latest_log['timestamp'] if latest_log else 'No activity yet',
    })

# ═══════════════════════════════════════════════════════════════
#  IT SUPPORT — RECEIVE & MANAGE BANKING TICKETS
# ═══════════════════════════════════════════════════════════════

@app.route('/it-support')
@login_required
def it_support():
    """IT Support page — view and respond to banking tickets."""
    db = get_db()

    status_filter = request.args.get('status', '').strip()
    category_filter = request.args.get('category', '').strip()

    query  = 'SELECT * FROM bank_tickets WHERE 1=1'
    params = []
    if status_filter:
        query += ' AND status = ?'
        params.append(status_filter)
    if category_filter:
        query += ' AND category = ?'
        params.append(category_filter)
    query += ' ORDER BY created_at DESC'

    tickets = db.execute(query, params).fetchall()

    # Stats
    total_tickets  = db.execute('SELECT COUNT(*) FROM bank_tickets').fetchone()[0]
    open_tickets   = db.execute('SELECT COUNT(*) FROM bank_tickets WHERE status = "open"').fetchone()[0]
    resolved_tickets = db.execute('SELECT COUNT(*) FROM bank_tickets WHERE status = "resolved"').fetchone()[0]
    in_progress    = db.execute('SELECT COUNT(*) FROM bank_tickets WHERE status = "in_progress"').fetchone()[0]
    alert_count    = db.execute('SELECT COUNT(*) FROM alerts WHERE status = "open"').fetchone()[0]

    db.close()

    return render_template('it_support.html',
                           tickets=tickets,
                           total_tickets=total_tickets,
                           open_tickets=open_tickets,
                           resolved_tickets=resolved_tickets,
                           in_progress=in_progress,
                           alert_count=alert_count,
                           status_filter=status_filter,
                           category_filter=category_filter)


@app.route('/it-support/respond/<int:ticket_id>', methods=['POST'])
@login_required
def it_support_respond(ticket_id):
    """Admin responds to a ticket and updates its status."""
    reply      = request.form.get('reply', '').strip()
    new_status = request.form.get('status', 'in_progress').strip()

    if not reply:
        flash('Please enter a reply before submitting.', 'danger')
        return redirect(url_for('it_support'))

    db = get_db()
    db.execute('''
        UPDATE bank_tickets
        SET admin_reply = ?,
            status      = ?,
            updated_at  = datetime('now')
        WHERE id = ?
    ''', (reply, new_status, ticket_id))
    db.commit()

    ticket = db.execute(
        'SELECT * FROM bank_tickets WHERE id = ?', (ticket_id,)
    ).fetchone()
    db.close()

    flash(
        f'✅ Reply sent to {ticket["client_name"]}. '
        f'Ticket status updated to "{new_status}".',
        'success'
    )
    return redirect(url_for('it_support'))

# ═══════════════════════════════════════════════════════════════
#  BANKING ALERTS — MANAGE PENDING TRANSACTIONS
# ═══════════════════════════════════════════════════════════════

@app.route('/banking-alerts')
@login_required
def banking_alerts():
    """Banking alerts page — review and approve/reject transactions."""
    db = get_db()

    status_filter = request.args.get('status', '').strip()
    query  = 'SELECT * FROM bank_transactions WHERE 1=1'
    params = []
    if status_filter:
        query += ' AND status = ?'
        params.append(status_filter)
    query += ' ORDER BY created_at DESC'

    transactions = db.execute(query, params).fetchall()

    # Stats
    pending_count  = db.execute(
        'SELECT COUNT(*) FROM bank_transactions WHERE status = "pending_review"'
    ).fetchone()[0]
    approved_count = db.execute(
        'SELECT COUNT(*) FROM bank_transactions WHERE status = "approved"'
    ).fetchone()[0]
    rejected_count = db.execute(
        'SELECT COUNT(*) FROM bank_transactions WHERE status = "rejected"'
    ).fetchone()[0]
    doc_requested  = db.execute(
        'SELECT COUNT(*) FROM bank_transactions WHERE status = "document_requested"'
    ).fetchone()[0]
    total_amount_pending = db.execute(
        'SELECT COALESCE(SUM(amount), 0) FROM bank_transactions WHERE status = "pending_review"'
    ).fetchone()[0]

    alert_count = db.execute(
        'SELECT COUNT(*) FROM alerts WHERE status = "open"'
    ).fetchone()[0]

    db.close()

    return render_template('banking_alerts.html',
                           transactions=transactions,
                           pending_count=pending_count,
                           approved_count=approved_count,
                           rejected_count=rejected_count,
                           doc_requested=doc_requested,
                           total_amount_pending=total_amount_pending,
                           alert_count=alert_count,
                           status_filter=status_filter)


@app.route('/banking-alerts/approve/<int:tx_id>', methods=['POST'])
@login_required
def approve_transaction(tx_id):
    """Approve a pending transaction."""
    db = get_db()
    tx = db.execute(
        'SELECT * FROM bank_transactions WHERE id = ?', (tx_id,)
    ).fetchone()

    if not tx:
        flash('Transaction not found.', 'danger')
        db.close()
        return redirect(url_for('banking_alerts'))

    db.execute('''
        UPDATE bank_transactions
        SET status         = "approved",
            admin_decision = "approved",
            updated_at     = datetime('now')
        WHERE id = ?
    ''', (tx_id,))
    db.commit()
    db.close()

    flash(
        f'✅ Transaction {tx["tx_ref"]} approved. '
        f'${tx["amount"]:.2f} transfer will be processed.',
        'success'
    )
    return redirect(url_for('banking_alerts'))


@app.route('/banking-alerts/reject/<int:tx_id>', methods=['POST'])
@login_required
def reject_transaction(tx_id):
    """Reject a pending transaction with a reason."""
    reason = request.form.get('reason', '').strip()
    if not reason:
        flash('Please provide a rejection reason.', 'danger')
        return redirect(url_for('banking_alerts'))

    db = get_db()
    tx = db.execute(
        'SELECT * FROM bank_transactions WHERE id = ?', (tx_id,)
    ).fetchone()

    if not tx:
        flash('Transaction not found.', 'danger')
        db.close()
        return redirect(url_for('banking_alerts'))

    db.execute('''
        UPDATE bank_transactions
        SET status           = "rejected",
            admin_decision   = "rejected",
            rejection_reason = ?,
            updated_at       = datetime('now')
        WHERE id = ?
    ''', (reason, tx_id))
    db.commit()
    db.close()

    flash(
        f'🚫 Transaction {tx["tx_ref"]} rejected. '
        f'Client will be notified.',
        'success'
    )
    return redirect(url_for('banking_alerts'))


@app.route('/banking-alerts/request-document/<int:tx_id>',
           methods=['POST'])
@login_required
def request_document(tx_id):
    """Request a document from the client before approving."""
    db = get_db()
    tx = db.execute(
        'SELECT * FROM bank_transactions WHERE id = ?', (tx_id,)
    ).fetchone()

    if not tx:
        flash('Transaction not found.', 'danger')
        db.close()
        return redirect(url_for('banking_alerts'))

    db.execute('''
        UPDATE bank_transactions
        SET status             = "document_requested",
            document_requested = 1,
            updated_at         = datetime('now')
        WHERE id = ?
    ''', (tx_id,))
    db.commit()
    db.close()

    flash(
        f'📄 Document requested from {tx["sender_name"]} '
        f'for transaction {tx["tx_ref"]}. '
        f'Client will be notified to upload.',
        'success'
    )
    return redirect(url_for('banking_alerts'))


@app.route('/banking-alerts/approve-with-doc/<int:tx_id>',
           methods=['POST'])
@login_required
def approve_with_document(tx_id):
    """Approve transaction after document has been uploaded."""
    db = get_db()
    tx = db.execute(
        'SELECT * FROM bank_transactions WHERE id = ?', (tx_id,)
    ).fetchone()

    if not tx:
        flash('Transaction not found.', 'danger')
        db.close()
        return redirect(url_for('banking_alerts'))

    if not tx['document_path']:
        flash('No document uploaded yet by the client.', 'danger')
        db.close()
        return redirect(url_for('banking_alerts'))

    db.execute('''
        UPDATE bank_transactions
        SET status         = "approved",
            admin_decision = "approved_with_document",
            updated_at     = datetime('now')
        WHERE id = ?
    ''', (tx_id,))
    db.commit()
    db.close()

    flash(
        f'✅ Transaction {tx["tx_ref"]} approved after '
        f'document verification.',
        'success'
    )
    return redirect(url_for('banking_alerts'))

# ═══════════════════════════════════════════════════════════════
#  REPORTS
# ═══════════════════════════════════════════════════════════════

@app.route('/reports')
@login_required
def reports():
    db = get_db()
    alert_count = db.execute('SELECT COUNT(*) FROM alerts WHERE status = "open"').fetchone()[0]
    db.close()
    return render_template('reports.html', alert_count=alert_count)

@app.route('/generate-report', methods=['POST'])
@login_required
def generate_report():
    date_from = request.form.get('date_from', '').strip()
    date_to   = request.form.get('date_to',   '').strip()
    if not date_from or not date_to:
        flash('Please select both start and end dates.', 'danger')
        return redirect(url_for('reports'))

    db = get_db()
    logs_data    = db.execute('SELECT * FROM logs WHERE date(timestamp) BETWEEN ? AND ? ORDER BY timestamp DESC', (date_from, date_to)).fetchall()
    alerts_data  = db.execute('SELECT * FROM alerts WHERE date(timestamp) BETWEEN ? AND ? ORDER BY timestamp DESC', (date_from, date_to)).fetchall()
    blocked_data = db.execute('SELECT * FROM blocked_ips ORDER BY blocked_at DESC').fetchall()
    db.close()

    total_logs        = len(logs_data)
    total_alerts      = len(alerts_data)
    total_blocked     = len(blocked_data)
    failed_logins     = sum(1 for l in logs_data if l['event_type'] == 'failed_login')
    successful_logins = sum(1 for l in logs_data if l['event_type'] == 'successful_login')
    suspicious_events = sum(1 for l in logs_data if l['event_type'] == 'suspicious_activity')
    high_alerts       = sum(1 for a in alerts_data if a['severity'] == 'high')
    medium_alerts     = sum(1 for a in alerts_data if a['severity'] == 'medium')
    open_alerts       = sum(1 for a in alerts_data if a['status'] == 'open')
    resolved_alerts   = sum(1 for a in alerts_data if a['status'] == 'resolved')

    buffer = io.BytesIO()
    doc    = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=2*cm, leftMargin=2*cm, topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    style_title    = ParagraphStyle('T', parent=styles['Title'], fontSize=22, textColor=colors.HexColor('#1a1a2e'), spaceAfter=6, alignment=TA_CENTER, fontName='Helvetica-Bold')
    style_subtitle = ParagraphStyle('S', parent=styles['Normal'], fontSize=11, textColor=colors.HexColor('#555555'), spaceAfter=4, alignment=TA_CENTER)
    style_section  = ParagraphStyle('H', parent=styles['Heading2'], fontSize=13, textColor=colors.HexColor('#1a1a2e'), spaceBefore=16, spaceAfter=8, fontName='Helvetica-Bold')
    style_body     = ParagraphStyle('B', parent=styles['Normal'], fontSize=9, textColor=colors.HexColor('#333333'), spaceAfter=4, leading=14)
    style_small    = ParagraphStyle('Sm', parent=styles['Normal'], fontSize=8, textColor=colors.HexColor('#666666'), leading=12)

    elements = []
    elements.append(Spacer(1, 0.3*inch))
    elements.append(Paragraph('SecureWatch', style_title))
    elements.append(Paragraph('Security Monitoring System — Incident Report', style_subtitle))
    elements.append(Paragraph(f'Report Period: {date_from} to {date_to}', style_subtitle))
    elements.append(Paragraph(f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | By: {session.get("user", "Admin")}', style_subtitle))
    elements.append(Spacer(1, 0.1*inch))
    elements.append(HRFlowable(width='100%', thickness=2, color=colors.HexColor('#1a1a2e')))
    elements.append(Spacer(1, 0.2*inch))
    elements.append(Paragraph('1. Executive Summary', style_section))

    summary_data = [
        ['Metric', 'Value', 'Metric', 'Value'],
        ['Total Logs', str(total_logs), 'Total Alerts', str(total_alerts)],
        ['Failed Logins', str(failed_logins), 'Open Alerts', str(open_alerts)],
        ['Successful Logins', str(successful_logins), 'Resolved Alerts', str(resolved_alerts)],
        ['Suspicious Events', str(suspicious_events), 'Blocked IPs', str(total_blocked)],
        ['High Severity', str(high_alerts), 'Medium Severity', str(medium_alerts)],
    ]
    t = Table(summary_data, colWidths=[4.5*cm, 3*cm, 4.5*cm, 3*cm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1a1a2e')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#f8f9fa'), colors.white]),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dddddd')),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 0.15*inch))

    elements.append(Paragraph('2. Security Alerts', style_section))
    if alerts_data:
        at_data = [['#', 'IP Address', 'Alert Type', 'Severity', 'Status', 'Timestamp']]
        for i, a in enumerate(alerts_data[:30], 1):
            at_data.append([str(i), a['ip_address'], a['alert_type'], a['severity'].upper(), a['status'].capitalize(), str(a['timestamp'])[:16]])
        at = Table(at_data, colWidths=[1*cm, 3.5*cm, 4.5*cm, 2.5*cm, 2.5*cm, 3.5*cm])
        at.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#c0392b')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dddddd')),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#fff5f5'), colors.white]),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ]))
        elements.append(at)
    else:
        elements.append(Paragraph('No alerts in this period.', style_body))

    elements.append(Spacer(1, 0.15*inch))
    elements.append(Paragraph('3. Log Activity Summary', style_section))
    if logs_data:
        lt_data = [['#', 'IP Address', 'Event Type', 'Message', 'Source', 'Time']]
        for i, l in enumerate(logs_data[:30], 1):
            lt_data.append([str(i), l['ip_address'], l['event_type'].replace('_',' ').title(), (l['message'] or '')[:40], l['source'] or 'system', str(l['timestamp'])[:16]])
        lt = Table(lt_data, colWidths=[1*cm, 3.5*cm, 3.5*cm, 4*cm, 2*cm, 3.5*cm])
        lt.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1a1a2e')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dddddd')),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#f8f9fa'), colors.white]),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ]))
        elements.append(lt)
    else:
        elements.append(Paragraph('No logs recorded in this period.', style_body))

    elements.append(Spacer(1, 0.15*inch))
    elements.append(Paragraph('4. Blocked IP Addresses', style_section))
    if blocked_data:
        bt_data = [['#', 'IP Address', 'Reason', 'Blocked At']]
        for i, b in enumerate(blocked_data, 1):
            bt_data.append([str(i), b['ip_address'], b['reason'] or '—', str(b['blocked_at'])[:16]])
        bt = Table(bt_data, colWidths=[1*cm, 4*cm, 7*cm, 4*cm])
        bt.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#7b2d2d')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dddddd')),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#fff5f5'), colors.white]),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ]))
        elements.append(bt)
    else:
        elements.append(Paragraph('No IPs are currently blocked.', style_body))

    elements.append(Spacer(1, 0.2*inch))
    elements.append(HRFlowable(width='100%', thickness=1, color=colors.HexColor('#cccccc')))
    elements.append(Spacer(1, 0.1*inch))
    elements.append(Paragraph(
        f'SecureWatch Security Monitoring System | Confidential | Generated {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}',
        ParagraphStyle('Footer', parent=styles['Normal'], fontSize=7, textColor=colors.HexColor('#999999'), alignment=TA_CENTER)
    ))

    doc.build(elements)
    buffer.seek(0)
    filename = f'SecureWatch_Report_{date_from}_to_{date_to}.pdf'
    response = make_response(buffer.read())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response

# ═══════════════════════════════════════════════════════════════
#  API — RECEIVE LOGS FROM EXTERNAL SOURCES
# ═══════════════════════════════════════════════════════════════

@app.route('/api/logs', methods=['POST'])
def api_receive_logs():
    api_key = request.headers.get('X-API-Key', '')
    if api_key != 'securewatch-api-key-2024':
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data received'}), 400
    ip_address = data.get('ip_address', '').strip()
    event_type = data.get('event_type', '').strip()
    message    = data.get('message',    '').strip()
    source     = data.get('source',     'external').strip()
    if not ip_address or not event_type:
        return jsonify({'error': 'ip_address and event_type are required'}), 400
    db = get_db()
    db.execute('INSERT INTO logs (ip_address, event_type, message, source) VALUES (?, ?, ?, ?)',
               (ip_address, event_type, message, source))
    db.commit()
    db.close()
    try:
        run_detection(ip_address, event_type)
    except Exception as e:
        print(f'Detection error: {e}')
    return jsonify({'status': 'success', 'message': 'Log received and processed'}), 201

# ═══════════════════════════════════════════════════════════════
#  API — BANKING TICKETS (from webapp)
# ═══════════════════════════════════════════════════════════════

@app.route('/api/banking/ticket', methods=['POST'])
def api_receive_ticket():
    """Receive support ticket from banking webapp."""
    api_key = request.headers.get('X-API-Key', '')
    if api_key != 'securewatch-api-key-2024':
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data'}), 400

    db = get_db()
    db.execute('''
        INSERT INTO bank_tickets
            (ticket_ref, username, client_name, category,
             subject, message, ip_address)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        data.get('ticket_ref'),
        data.get('username'),
        data.get('client_name'),
        data.get('category'),
        data.get('subject'),
        data.get('message'),
        data.get('ip_address'),
    ))
    db.commit()
    db.close()
    return jsonify({'status': 'success',
                    'ticket_ref': data.get('ticket_ref')}), 201


@app.route('/api/banking/ticket-status')
def api_ticket_status():
    """Webapp polls this to get ticket status and admin reply."""
    api_key = request.headers.get('X-API-Key', '')
    if api_key != 'securewatch-api-key-2024':
        return jsonify({'error': 'Unauthorized'}), 401

    ticket_ref = request.args.get('ref', '').strip()
    if not ticket_ref:
        return jsonify({'error': 'No ticket ref'}), 400

    db     = get_db()
    ticket = db.execute(
        'SELECT * FROM bank_tickets WHERE ticket_ref = ?',
        (ticket_ref,)
    ).fetchone()
    db.close()

    if not ticket:
        return jsonify({'error': 'Ticket not found'}), 404

    return jsonify({
        'ticket_ref':  ticket['ticket_ref'],
        'status':      ticket['status'],
        'admin_reply': ticket['admin_reply'],
        'updated_at':  ticket['updated_at'],
    })

# ═══════════════════════════════════════════════════════════════
#  API — BANKING TRANSACTIONS (from webapp)
# ═══════════════════════════════════════════════════════════════

@app.route('/api/banking/transaction', methods=['POST'])
def api_receive_transaction():
    """Receive large transaction for admin review."""
    api_key = request.headers.get('X-API-Key', '')
    if api_key != 'securewatch-api-key-2024':
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data'}), 400

    db = get_db()
    db.execute('''
        INSERT INTO bank_transactions
            (tx_ref, sender_username, sender_name,
             recipient_name, amount, note, ip_address)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        data.get('tx_ref'),
        data.get('sender_username'),
        data.get('sender_name'),
        data.get('recipient_name'),
        data.get('amount'),
        data.get('note', ''),
        data.get('ip_address'),
    ))
    db.commit()
    db.close()
    return jsonify({'status': 'pending_review',
                    'tx_ref': data.get('tx_ref')}), 201


@app.route('/api/banking/transaction-status')
def api_transaction_status():
    """Webapp polls this to get transaction decision."""
    api_key = request.headers.get('X-API-Key', '')
    if api_key != 'securewatch-api-key-2024':
        return jsonify({'error': 'Unauthorized'}), 401

    tx_ref = request.args.get('ref', '').strip()
    if not tx_ref:
        return jsonify({'error': 'No tx ref'}), 400

    db = get_db()
    tx = db.execute(
        'SELECT * FROM bank_transactions WHERE tx_ref = ?',
        (tx_ref,)
    ).fetchone()
    db.close()

    if not tx:
        return jsonify({'error': 'Transaction not found'}), 404

    return jsonify({
        'tx_ref':              tx['tx_ref'],
        'status':              tx['status'],
        'admin_decision':      tx['admin_decision'],
        'rejection_reason':    tx['rejection_reason'],
        'document_requested':  bool(tx['document_requested']),
        'document_uploaded':   bool(tx['document_path']),
        'updated_at':          tx['updated_at'],
    })


@app.route('/api/banking/upload-document', methods=['POST'])
def api_upload_document():
    """Client uploads approval document."""
    api_key = request.headers.get('X-API-Key', '')
    if api_key != 'securewatch-api-key-2024':
        return jsonify({'error': 'Unauthorized'}), 401

    tx_ref = request.form.get('tx_ref', '').strip()
    file   = request.files.get('document')

    if not tx_ref or not file:
        return jsonify({'error': 'tx_ref and document required'}), 400

    allowed = {'pdf', 'jpg', 'jpeg', 'png', 'doc', 'docx'}
    ext     = file.filename.rsplit('.', 1)[-1].lower()
    if ext not in allowed:
        return jsonify({'error': 'File type not allowed'}), 400

    filename  = f'{tx_ref}_document.{ext}'
    save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(save_path)

    db = get_db()
    db.execute('''
        UPDATE bank_transactions
        SET document_path = ?, updated_at = datetime('now')
        WHERE tx_ref = ?
    ''', (filename, tx_ref))
    db.commit()
    db.close()

    return jsonify({'status': 'uploaded', 'filename': filename}), 200

# ═══════════════════════════════════════════════════════════════
#  RUN APP
# ═══════════════════════════════════════════════════════════════

if __name__ == '__main__':
    app.run(debug=True, port=5000)
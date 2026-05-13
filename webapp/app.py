from flask import (Flask, render_template, request,
                   redirect, url_for, session, flash, jsonify)
import requests
from datetime import datetime
import random

app = Flask(__name__)
app.secret_key = 'techcorp_bank_secret_2024'

# ── SECUREWATCH URLS ─────────────────────────────────────────────
MAIN_SYSTEM_URL    = 'http://127.0.0.1:5000/api/logs'
MAIN_BLOCKED_URL   = 'http://127.0.0.1:5000/api/is-blocked'
MAIN_TICKET_URL    = 'http://127.0.0.1:5000/api/banking/ticket'
MAIN_TICKET_STATUS = 'http://127.0.0.1:5000/api/banking/ticket-status'
MAIN_TX_URL        = 'http://127.0.0.1:5000/api/banking/transaction'
MAIN_TX_STATUS     = 'http://127.0.0.1:5000/api/banking/transaction-status'
MAIN_TX_DOC_UPLOAD = 'http://127.0.0.1:5000/api/banking/upload-document'
API_KEY            = 'securewatch-api-key-2024'

# ═══════════════════════════════════════════════════════════════
#  ACCOUNTS
# ═══════════════════════════════════════════════════════════════

ACCOUNTS = {
    'Nsaila': {
        'password':       'bank123',
        'name':           'Nsaila Ridley',
        'account_number': '0650196647',
        'balance':        2000000.00,
        'account_type':   'Current Account',
        'card_number':    '7896 6060 9001 4521',
        'card_expiry':    '09/27',
        'card_frozen':    False,
        'card_limit':     500000.00,
    },
    'Sibarah': {
        'password':       'bank456',
        'name':           'Sibarah Pavel',
        'account_number': '0621039657',
        'balance':        832000.50,
        'account_type':   'Current Account',
        'card_number':    '2356 4040 8892 7823',
        'card_expiry':    '12/28',
        'card_frozen':    False,
        'card_limit':     300000.00,
    },
    'Ridley': {
        'password':       'bank789',
        'name':           'Nsaila Ridley N',
        'account_number': '00650196647',
        'balance':        25100.75,
        'account_type':   'Savings Account',
        'card_number':    '9090 7863 3864 1190',
        'card_expiry':    '03/28',
        'card_frozen':    False,
        'card_limit':     500000.00,
    },
    'admin': {
        'password':       'bankadmin',
        'name':           'Admin Manager',
        'account_number': 'TC-0000-0001',
        'balance':        999999.00,
        'account_type':   'Manager Account',
        'card_number':    '**** **** **** 0001',
        'card_expiry':    '01/30',
        'card_frozen':    False,
        'card_limit':     50000.00,
    },
}

# ── TRANSACTIONS ─────────────────────────────────────────────────
TRANSACTIONS = {
    'Nsaila': [
        {'id': 'TXN001', 'type': 'credit',
         'description': 'Initial Deposit',
         'amount': 2000000.00, 'date': '2024-05-01',
         'status': 'completed', 'tx_ref': None},
    ],
    'Sibarah': [
        {'id': 'TXN010', 'type': 'credit',
         'description': 'Initial Deposit',
         'amount': 832000.50, 'date': '2024-05-01',
         'status': 'completed', 'tx_ref': None},
    ],
    'Ridley': [
        {'id': 'TXN020', 'type': 'credit',
         'description': 'Initial Deposit',
         'amount': 25100.75, 'date': '2024-05-01',
         'status': 'completed', 'tx_ref': None},
    ],
    'admin': [],
}

# ── TICKETS ──────────────────────────────────────────────────────
TICKETS = {
    'Nsaila': [], 'Sibarah': [], 'Ridley': [], 'admin': []
}

# ── PENDING LARGE TRANSFERS ──────────────────────────────────────
PENDING = {}

# ═══════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════

def send_log(ip, event_type, message):
    try:
        requests.post(
            MAIN_SYSTEM_URL,
            json={
                'ip_address': ip,
                'event_type': event_type,
                'message':    message,
                'source':     'techcorp_banking',
            },
            headers={
                'X-API-Key':    API_KEY,
                'Content-Type': 'application/json',
            },
            timeout=3
        )
    except Exception as e:
        print(f'Log error: {e}')


def is_ip_blocked(ip):
    try:
        r = requests.get(
            MAIN_BLOCKED_URL,
            params={'ip': ip},
            headers={'X-API-Key': API_KEY},
            timeout=3
        )
        if r.status_code == 200:
            return r.json().get('blocked', False)
    except Exception:
        pass
    return False


def send_ticket(data):
    try:
        r = requests.post(
            MAIN_TICKET_URL,
            json=data,
            headers={
                'X-API-Key':    API_KEY,
                'Content-Type': 'application/json',
            },
            timeout=3
        )
        return r.status_code == 201
    except Exception:
        return False


def fetch_ticket_status(ref):
    try:
        r = requests.get(
            MAIN_TICKET_STATUS,
            params={'ref': ref},
            headers={'X-API-Key': API_KEY},
            timeout=3
        )
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


def submit_tx_for_review(data):
    try:
        r = requests.post(
            MAIN_TX_URL,
            json=data,
            headers={
                'X-API-Key':    API_KEY,
                'Content-Type': 'application/json',
            },
            timeout=3
        )
        return r.status_code == 201
    except Exception:
        return False


def fetch_tx_status(ref):
    """Returns clean dict with guaranteed string status."""
    try:
        r = requests.get(
            MAIN_TX_STATUS,
            params={'ref': ref},
            headers={'X-API-Key': API_KEY},
            timeout=3
        )
        if r.status_code == 200:
            data = r.json()

            raw = data.get('status', '')
            if not isinstance(raw, str):
                raw = str(raw)
            data['status'] = raw

            data['document_uploaded'] = bool(
                data.get('document_uploaded', False))
            data['document_requested'] = bool(
                data.get('document_requested', False))

            return data
    except Exception as e:
        print(f'fetch_tx_status error: {e}')
    return None


def process_approved_transfer(tx_ref):
    """Execute money movement for an approved transfer."""
    pending = PENDING.get(tx_ref)
    if not pending:
        return False
    if pending.get('processed'):
        return False

    sender_key    = pending['sender_username']
    recipient_key = pending['recipient_key']
    amount        = pending['amount']
    note          = pending.get('note', '')
    date          = pending['date']

    sender_name    = ACCOUNTS.get(sender_key, {}).get(
        'name', sender_key)
    recipient_name = ACCOUNTS.get(recipient_key, {}).get(
        'name', recipient_key)

    if sender_key in ACCOUNTS:
        ACCOUNTS[sender_key]['balance'] -= amount

    if recipient_key in ACCOUNTS:
        ACCOUNTS[recipient_key]['balance'] += amount

    credit_id = tx_ref + '_CREDIT'
    if recipient_key not in TRANSACTIONS:
        TRANSACTIONS[recipient_key] = []

    already = any(
        t.get('id') == credit_id
        for t in TRANSACTIONS[recipient_key]
    )
    if not already:
        TRANSACTIONS[recipient_key].append({
            'id':          credit_id,
            'type':        'credit',
            'description': (
                f'Transfer from {sender_name}'
                + (f' — {note}' if note else '')
                + ' (Security Approved)'
            ),
            'amount':      amount,
            'date':        date,
            'status':      'completed',
            'tx_ref':      credit_id,
        })

    for tx in TRANSACTIONS.get(sender_key, []):
        if tx.get('tx_ref') == tx_ref:
            tx['status'] = 'completed'
            break

    PENDING[tx_ref]['processed'] = True
    PENDING[tx_ref]['sw_status'] = 'approved'

    print(f'✅ Transfer processed: '
          f'FCFA {amount:,.2f} '
          f'{sender_name} → {recipient_name}')
    return True


def generate_tx_id():
    return 'TXN' + str(random.randint(100000, 999999))


def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            flash('Please log in to access your account.',
                  'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


# ═══════════════════════════════════════════════════════════════
#  AUTH
# ═══════════════════════════════════════════════════════════════

@app.route('/')
def index():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/login', methods=['GET'])
def login():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def login_post():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    ip       = request.remote_addr

    if is_ip_blocked(ip):
        send_log(ip, 'blocked_access',
                 f'Blocked IP tried banking portal '
                 f'as "{username}"')
        return render_template('blocked.html', ip_address=ip)

    account = ACCOUNTS.get(username)
    if account and account['password'] == password:
        session['user'] = username
        send_log(ip, 'successful_login',
                 f'User "{account["name"]}" logged in')
        flash(f'Welcome back, {account["name"]}!', 'success')
        return redirect(url_for('dashboard'))
    else:
        send_log(ip, 'failed_login',
                 f'Failed login attempt for "{username}"')
        flash('Invalid username or password.', 'danger')
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    username = session.get('user', '')
    account  = ACCOUNTS.get(username)
    name     = account['name'] if account else username
    send_log(request.remote_addr, 'successful_login',
             f'User "{name}" logged out')
    session.clear()
    flash('You have been logged out securely.', 'success')
    return redirect(url_for('login'))


# ═══════════════════════════════════════════════════════════════
#  DASHBOARD
# ═══════════════════════════════════════════════════════════════

@app.route('/dashboard')
@login_required
def dashboard():
    username = session['user']
    account  = ACCOUNTS[username]
    txns     = TRANSACTIONS.get(username, [])
    send_log(request.remote_addr, 'page_visit',
             f'User "{account["name"]}" viewed dashboard')
    recent_txns = txns[-5:][::-1]
    total_in  = sum(
        t['amount'] for t in txns if t['type'] == 'credit')
    total_out = sum(
        t['amount'] for t in txns if t['type'] == 'debit')
    return render_template('dashboard.html',
                           account=account,
                           username=username,
                           recent_txns=recent_txns,
                           total_in=total_in,
                           total_out=total_out)


# ═══════════════════════════════════════════════════════════════
#  TRANSFER
# ═══════════════════════════════════════════════════════════════

@app.route('/transfer', methods=['GET'])
@login_required
def transfer():
    username   = session['user']
    account    = ACCOUNTS[username]
    recipients = {k: v for k, v in ACCOUNTS.items()
                  if k != username}
    send_log(request.remote_addr, 'page_visit',
             f'User "{account["name"]}" visited transfer page')
    return render_template('transfer.html',
                           account=account,
                           username=username,
                           recipients=recipients)


@app.route('/transfer', methods=['POST'])
@login_required
def transfer_post():
    username      = session['user']
    account       = ACCOUNTS[username]
    ip            = request.remote_addr
    recipient_key = request.form.get('recipient', '').strip()
    note          = request.form.get('note', '').strip()

    try:
        amount = float(
            request.form.get('amount', '0').strip())
    except ValueError:
        flash('Invalid amount.', 'danger')
        return redirect(url_for('transfer'))

    if amount <= 0:
        flash('Amount must be greater than zero.', 'danger')
        return redirect(url_for('transfer'))

    if amount > account['balance']:
        flash('Insufficient funds.', 'danger')
        send_log(ip, 'suspicious_activity',
                 f'"{account["name"]}" attempted '
                 f'FCFA {amount:,.2f} with insufficient funds')
        return redirect(url_for('transfer'))

    recipient = ACCOUNTS.get(recipient_key)
    if not recipient:
        flash('Invalid recipient.', 'danger')
        return redirect(url_for('transfer'))

    tx_id = generate_tx_id()
    now   = datetime.now().strftime('%Y-%m-%d')

    # ── LARGE TRANSFER → needs admin review ───────────────────
    if amount >= 5000:
        tx_data = {
            'tx_ref':          tx_id,
            'sender_username': username,
            'sender_name':     account['name'],
            'recipient_name':  recipient['name'],
            'amount':          amount,
            'note':            note,
            'ip_address':      ip,
        }

        sent = submit_tx_for_review(tx_data)

        if sent:
            PENDING[tx_id] = {
                'sender_username': username,
                'recipient_key':   recipient_key,
                'amount':          amount,
                'note':            note,
                'recipient_name':  recipient['name'],
                'date':            now,
                'processed':       False,
                'sw_status':       'pending_review',
            }

            if username not in TRANSACTIONS:
                TRANSACTIONS[username] = []

            TRANSACTIONS[username].append({
                'id':          tx_id,
                'type':        'debit',
                'description': (
                    f'Transfer to {recipient["name"]}'
                    + (f' — {note}' if note else '')
                ),
                'amount':      amount,
                'date':        now,
                'status':      'under_review',
                'tx_ref':      tx_id,
            })

            send_log(ip, 'suspicious_activity',
                     f'LARGE TRANSFER FLAGGED: '
                     f'"{account["name"]}" → '
                     f'FCFA {amount:,.2f} → '
                     f'"{recipient["name"]}" '
                     f'(Ref: {tx_id})')

            flash(
                f'⚠️ Transfer of FCFA {amount:,.2f} to '
                f'{recipient["name"]} requires security '
                f'review. Reference: {tx_id}. '
                f'Check your Transactions page for updates.',
                'warning'
            )
        else:
            flash('Transfer could not be submitted. '
                  'Please try again.', 'danger')

        return redirect(url_for('transactions'))

    # ── NORMAL TRANSFER → process immediately ─────────────────
    ACCOUNTS[username]['balance']      -= amount
    ACCOUNTS[recipient_key]['balance'] += amount

    if username not in TRANSACTIONS:
        TRANSACTIONS[username] = []

    TRANSACTIONS[username].append({
        'id':          tx_id,
        'type':        'debit',
        'description': (
            f'Transfer to {recipient["name"]}'
            + (f' — {note}' if note else '')
        ),
        'amount':      amount,
        'date':        now,
        'status':      'completed',
        'tx_ref':      None,
    })

    if recipient_key not in TRANSACTIONS:
        TRANSACTIONS[recipient_key] = []

    TRANSACTIONS[recipient_key].append({
        'id':          tx_id + '_CREDIT',
        'type':        'credit',
        'description': (
            f'Transfer from {account["name"]}'
            + (f' — {note}' if note else '')
        ),
        'amount':      amount,
        'date':        now,
        'status':      'completed',
        'tx_ref':      None,
    })

    send_log(ip, 'fund_transfer',
             f'Transfer: "{account["name"]}" sent '
             f'FCFA {amount:,.2f} to "{recipient["name"]}" '
             f'(Ref: {tx_id})')

    flash(
        f'✅ Transfer of FCFA {amount:,.2f} to '
        f'{recipient["name"]} completed! '
        f'Reference: {tx_id}',
        'success'
    )
    return redirect(url_for('transactions'))


# ═══════════════════════════════════════════════════════════════
#  TRANSACTIONS
# ═══════════════════════════════════════════════════════════════

@app.route('/transactions')
@login_required
def transactions():
    username = session['user']
    account  = ACCOUNTS[username]
    txns     = TRANSACTIONS.get(username, [])

    send_log(request.remote_addr, 'sensitive_access',
             f'User "{account["name"]}" viewed transactions')

    pending_statuses    = {}
    doc_request_txns    = []
    pending_review_txns = []

    for tx in txns:
        tx_ref       = tx.get('tx_ref') or ''
        local_status = tx.get('status', '')

        if tx_ref and local_status not in [
            'completed', 'rejected'
        ]:
            sw = fetch_tx_status(tx_ref)

            if sw is not None:
                sw_status = sw.get('status', '')
                if not isinstance(sw_status, str):
                    sw_status = str(sw_status)

                doc_uploaded  = bool(
                    sw.get('document_uploaded', False))
                doc_requested = bool(
                    sw.get('document_requested', False))

                pending_statuses[tx_ref] = sw

                valid_statuses = [
                    'pending_review',
                    'document_requested',
                    'document_uploaded',
                    'approved',
                    'rejected',
                ]
                if sw_status in valid_statuses:
                    tx['status'] = sw_status

                if tx_ref in PENDING:
                    PENDING[tx_ref]['sw_status'] = sw_status

                if sw_status == 'approved':
                    p = PENDING.get(tx_ref, {})
                    if not p.get('processed'):
                        process_approved_transfer(tx_ref)
                    tx['status'] = 'completed'

                elif sw_status == 'document_requested':
                    if not doc_uploaded:
                        tx['status'] = 'document_requested'
                        doc_request_txns.append(tx)
                    else:
                        tx['status'] = 'document_uploaded'
                        pending_review_txns.append(tx)

                elif sw_status in [
                    'pending_review', 'under_review'
                ]:
                    tx['status'] = 'under_review'
                    pending_review_txns.append(tx)

            else:
                pending_statuses[tx_ref] = {
                    'status':             local_status,
                    'document_uploaded':  False,
                    'document_requested': False,
                }
                if local_status in [
                    'under_review', 'pending_review'
                ]:
                    pending_review_txns.append(tx)
                elif local_status == 'document_requested':
                    doc_request_txns.append(tx)

    return render_template(
        'transactions.html',
        account=account,
        username=username,
        transactions=txns[::-1],
        pending_statuses=pending_statuses,
        doc_request_txns=doc_request_txns,
        pending_review_txns=pending_review_txns,
    )


@app.route('/refresh-pending')
@login_required
def refresh_pending():
    flash('Transaction statuses refreshed.', 'info')
    return redirect(url_for('transactions'))


@app.route('/check-transaction-status/<tx_ref>')
@login_required
def check_transaction_status(tx_ref):
    username = session['user']
    account  = ACCOUNTS[username]

    sw = fetch_tx_status(tx_ref)
    if not sw:
        flash('Could not reach SecureWatch. Try again.',
              'danger')
        return redirect(url_for('transactions'))

    status = sw['status']

    txns     = TRANSACTIONS.get(username, [])
    tx_local = next(
        (t for t in txns if t.get('tx_ref') == tx_ref),
        None
    )

    if tx_local:
        tx_local['status'] = status

    if status == 'approved':
        p = PENDING.get(tx_ref, {})
        if not p.get('processed'):
            process_approved_transfer(tx_ref)
            flash(
                f'✅ Transfer of '
                f'FCFA {p.get("amount", 0):,.2f} to '
                f'{p.get("recipient_name", "")} '
                f'approved and processed!',
                'success'
            )
        else:
            flash('Transfer already processed.', 'info')

    elif status == 'rejected':
        reason = sw.get('rejection_reason',
                        'No reason given')
        flash(
            f'🚫 Transfer rejected. Reason: {reason}',
            'danger'
        )

    elif status == 'document_requested':
        if tx_local:
            tx_local['status'] = 'document_requested'
        flash(
            '📄 Please upload a document using the '
            'Upload column in the transactions table.',
            'warning'
        )

    else:
        flash('⏳ Transfer is still under review.', 'info')

    return redirect(url_for('transactions'))


@app.route(
    '/upload-transaction-document/<tx_ref>',
    methods=['POST']
)
@login_required
def upload_transaction_document(tx_ref):
    """Upload approval document for a large transfer."""
    file = request.files.get('document')

    if not file or file.filename == '':
        flash('Please select a document first.', 'danger')
        return redirect(url_for('transactions'))

    username = session['user']
    txns     = TRANSACTIONS.get(username, [])
    tx_local = next(
        (t for t in txns if t.get('tx_ref') == tx_ref),
        None
    )

    try:
        r = requests.post(
            MAIN_TX_DOC_UPLOAD,
            data={'tx_ref': tx_ref},
            files={
                'document': (
                    file.filename,
                    file.stream,
                    file.content_type
                    or 'application/octet-stream'
                )
            },
            headers={'X-API-Key': API_KEY},
            timeout=15
        )

        if r.status_code == 200:
            if tx_local:
                tx_local['status'] = 'document_uploaded'
            if tx_ref in PENDING:
                PENDING[tx_ref]['sw_status'] = \
                    'document_uploaded'
            flash(
                f'✅ Document uploaded for {tx_ref}. '
                f'SecureWatch admin will review and '
                f'approve your transfer shortly.',
                'success'
            )
        else:
            flash(
                f'Upload failed (HTTP {r.status_code}). '
                f'Please try again.',
                'danger'
            )

    except requests.exceptions.Timeout:
        flash('Upload timed out. Please try again.',
              'danger')
    except Exception as e:
        flash(f'Upload error: {str(e)}', 'danger')

    return redirect(url_for('transactions'))


# ═══════════════════════════════════════════════════════════════
#  CARDS
# ═══════════════════════════════════════════════════════════════

@app.route('/cards')
@login_required
def cards():
    username = session['user']
    account  = ACCOUNTS[username]
    send_log(request.remote_addr, 'sensitive_access',
             f'User "{account["name"]}" viewed cards')
    return render_template('cards.html',
                           account=account,
                           username=username)


@app.route('/freeze-card', methods=['POST'])
@login_required
def freeze_card():
    username = session['user']
    account  = ACCOUNTS[username]
    ACCOUNTS[username]['card_frozen'] = True
    send_log(request.remote_addr, 'card_freeze',
             f'"{account["name"]}" FROZE their card')
    flash('🔒 Card frozen successfully.', 'success')
    return redirect(url_for('cards'))


@app.route('/unfreeze-card', methods=['POST'])
@login_required
def unfreeze_card():
    username = session['user']
    account  = ACCOUNTS[username]
    ACCOUNTS[username]['card_frozen'] = False
    send_log(request.remote_addr, 'card_unfreeze',
             f'"{account["name"]}" UNFROZE their card')
    flash('✅ Card unfrozen successfully.', 'success')
    return redirect(url_for('cards'))


# ═══════════════════════════════════════════════════════════════
#  SUPPORT
# ═══════════════════════════════════════════════════════════════

@app.route('/support')
@login_required
def support():
    username = session['user']
    account  = ACCOUNTS[username]
    tickets  = TICKETS.get(username, [])

    send_log(request.remote_addr, 'page_visit',
             f'User "{account["name"]}" visited support')

    for ticket in tickets:
        ref = ticket.get('ticket_ref')
        if ref:
            data = fetch_ticket_status(ref)
            if data:
                ticket['status'] = data.get(
                    'status', ticket.get('status', 'open'))
                ticket['admin_reply'] = data.get(
                    'admin_reply')
                ticket['updated_at'] = data.get(
                    'updated_at')

    return render_template('support.html',
                           account=account,
                           username=username,
                           tickets=tickets)


@app.route('/support', methods=['POST'])
@login_required
def support_post():
    username = session['user']
    account  = ACCOUNTS[username]
    ip       = request.remote_addr

    subject  = request.form.get('subject',  '').strip()
    message  = request.form.get('message',  '').strip()
    category = request.form.get('category',
                                'general').strip()

    if not subject or not message:
        flash('Please fill in all fields.', 'danger')
        return redirect(url_for('support'))

    ticket_ref = 'TKT' + str(random.randint(10000, 99999))
    now        = datetime.now().strftime('%Y-%m-%d %H:%M')

    ticket_data = {
        'ticket_ref':  ticket_ref,
        'username':    username,
        'client_name': account['name'],
        'category':    category,
        'subject':     subject,
        'message':     message,
        'ip_address':  ip,
    }

    sent = send_ticket(ticket_data)

    if username not in TICKETS:
        TICKETS[username] = []

    TICKETS[username].append({
        'ticket_ref':  ticket_ref,
        'subject':     subject,
        'message':     message,
        'category':    category,
        'status':      'open',
        'admin_reply': None,
        'updated_at':  None,
        'date':        now,
    })

    send_log(ip, 'page_visit',
             f'"{account["name"]}" raised ticket '
             f'{ticket_ref}: "{subject}"')

    flash(
        f'✅ Ticket {ticket_ref} submitted to IT Support!'
        if sent else
        f'✅ Ticket {ticket_ref} saved locally.',
        'success' if sent else 'warning'
    )
    return redirect(url_for('support'))


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0',
            port=int(os.environ.get('PORT', 5001)))
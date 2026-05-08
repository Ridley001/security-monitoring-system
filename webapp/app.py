from flask import (Flask, render_template, request,
                   redirect, url_for, session, flash,
                   jsonify)
import requests
from datetime import datetime
import random
import os

# ── CREATE BANKING APP ───────────────────────────────────────────
app = Flask(__name__)
app.secret_key = 'techcorp_bank_secret_2024'

# ── SECUREWATCH CONNECTION ────────────────────────────────────────
MAIN_SYSTEM_URL     = 'http://127.0.0.1:5000/api/logs'
MAIN_BLOCKED_URL    = 'http://127.0.0.1:5000/api/is-blocked'
MAIN_TICKET_URL     = 'http://127.0.0.1:5000/api/banking/ticket'
MAIN_TICKET_STATUS  = 'http://127.0.0.1:5000/api/banking/ticket-status'
MAIN_TX_URL         = 'http://127.0.0.1:5000/api/banking/transaction'
MAIN_TX_STATUS      = 'http://127.0.0.1:5000/api/banking/transaction-status'
MAIN_TX_DOC_UPLOAD  = 'http://127.0.0.1:5000/api/banking/upload-document'
API_KEY             = 'securewatch-api-key-2024'

# ── ACCOUNT DATABASE ─────────────────────────────────────────────
ACCOUNTS = {
    'john':  {'password': 'bank123',   'name': 'John Mensah',
               'account_number': 'TC-4521-8834', 'balance': 12450.00,
               'account_type': 'Premium Checking',
               'card_number': '**** **** **** 4521',
               'card_expiry': '09/27', 'card_frozen': False,
               'card_limit': 5000.00},
    'sarah': {'password': 'bank456',   'name': 'Sarah Nkomo',
               'account_number': 'TC-7823-2291', 'balance': 8320.50,
               'account_type': 'Standard Savings',
               'card_number': '**** **** **** 7823',
               'card_expiry': '12/26', 'card_frozen': False,
               'card_limit': 3000.00},
    'mike':  {'password': 'bank789',   'name': 'Mike Okafor',
               'account_number': 'TC-1190-5567', 'balance': 25100.75,
               'account_type': 'Business Account',
               'card_number': '**** **** **** 1190',
               'card_expiry': '03/28', 'card_frozen': False,
               'card_limit': 10000.00},
    'admin': {'password': 'bankadmin', 'name': 'Admin Manager',
               'account_number': 'TC-0000-0001', 'balance': 999999.00,
               'account_type': 'Manager Account',
               'card_number': '**** **** **** 0001',
               'card_expiry': '01/30', 'card_frozen': False,
               'card_limit': 50000.00},
}

TRANSACTIONS = {
    'john':  [{'id': 'TXN001', 'type': 'credit', 'description': 'Salary Deposit',
                'amount': 3500.00, 'date': '2024-05-01', 'status': 'completed'},
               {'id': 'TXN002', 'type': 'debit',  'description': 'Online Shopping',
                'amount': 120.50, 'date': '2024-05-02', 'status': 'completed'},
               {'id': 'TXN003', 'type': 'debit',  'description': 'Restaurant Payment',
                'amount': 45.00,  'date': '2024-05-03', 'status': 'completed'}],
    'sarah': [{'id': 'TXN010', 'type': 'credit', 'description': 'Transfer Received',
                'amount': 500.00, 'date': '2024-05-01', 'status': 'completed'},
               {'id': 'TXN011', 'type': 'debit',  'description': 'Utility Bill',
                'amount': 89.00,  'date': '2024-05-02', 'status': 'completed'}],
    'mike':  [{'id': 'TXN020', 'type': 'credit', 'description': 'Business Revenue',
                'amount': 8000.00,'date': '2024-05-01', 'status': 'completed'},
               {'id': 'TXN021', 'type': 'debit',  'description': 'Supplier Payment',
                'amount': 2500.00,'date': '2024-05-02', 'status': 'completed'}],
    'admin': [],
}

TICKETS = {'john': [], 'sarah': [], 'mike': [], 'admin': []}

# Pending transactions waiting for admin review
PENDING_TRANSACTIONS = {}

# ═══════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════

def send_log(ip_address, event_type, message):
    try:
        requests.post(MAIN_SYSTEM_URL,
                      json={'ip_address': ip_address, 'event_type': event_type,
                            'message': message, 'source': 'techcorp_banking'},
                      headers={'X-API-Key': API_KEY, 'Content-Type': 'application/json'},
                      timeout=3)
    except Exception as e:
        print(f'Log send error: {e}')

def is_ip_blocked(ip_address):
    try:
        r = requests.get(MAIN_BLOCKED_URL, params={'ip': ip_address},
                         headers={'X-API-Key': API_KEY}, timeout=3)
        if r.status_code == 200:
            return r.json().get('blocked', False)
    except Exception:
        pass
    return False

def send_ticket_to_securewatch(ticket_data):
    try:
        r = requests.post(MAIN_TICKET_URL, json=ticket_data,
                          headers={'X-API-Key': API_KEY,
                                   'Content-Type': 'application/json'},
                          timeout=3)
        return r.status_code == 201
    except Exception as e:
        print(f'Ticket send error: {e}')
        return False

def get_ticket_status(ticket_ref):
    try:
        r = requests.get(MAIN_TICKET_STATUS, params={'ref': ticket_ref},
                         headers={'X-API-Key': API_KEY}, timeout=3)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None

def send_transaction_for_review(tx_data):
    try:
        r = requests.post(MAIN_TX_URL, json=tx_data,
                          headers={'X-API-Key': API_KEY,
                                   'Content-Type': 'application/json'},
                          timeout=3)
        return r.status_code == 201
    except Exception as e:
        print(f'TX send error: {e}')
        return False

def get_transaction_status(tx_ref):
    try:
        r = requests.get(MAIN_TX_STATUS, params={'ref': tx_ref},
                         headers={'X-API-Key': API_KEY}, timeout=3)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None

def generate_tx_id():
    return 'TXN' + str(random.randint(100000, 999999))

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            flash('Please log in to access your account.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def get_account(username):
    return ACCOUNTS.get(username)

def get_transactions(username):
    return TRANSACTIONS.get(username, [])

# ═══════════════════════════════════════════════════════════════
#  ROUTES
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
    username   = request.form.get('username', '').strip()
    password   = request.form.get('password', '').strip()
    ip_address = request.remote_addr

    if is_ip_blocked(ip_address):
        send_log(ip_address, 'blocked_access',
                 f'Blocked IP tried to access banking portal as "{username}"')
        return render_template('blocked.html', ip_address=ip_address)

    account = ACCOUNTS.get(username)
    if account and account['password'] == password:
        session['user'] = username
        send_log(ip_address, 'successful_login',
                 f'User "{account["name"]}" logged into banking portal')
        flash(f'Welcome back, {account["name"]}!', 'success')
        return redirect(url_for('dashboard'))
    else:
        send_log(ip_address, 'failed_login',
                 f'Failed banking login for username: "{username}"')
        flash('Invalid username or password.', 'danger')
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    username = session.get('user', 'Unknown')
    account  = get_account(username)
    name     = account['name'] if account else username
    send_log(request.remote_addr, 'successful_login',
             f'User "{name}" logged out')
    session.clear()
    flash('You have been logged out securely.', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    username = session['user']
    account  = get_account(username)
    txns     = get_transactions(username)
    send_log(request.remote_addr, 'page_visit',
             f'User "{account["name"]}" viewed dashboard')
    recent_txns = txns[-5:][::-1]
    total_in  = sum(t['amount'] for t in txns if t['type'] == 'credit')
    total_out = sum(t['amount'] for t in txns if t['type'] == 'debit')
    return render_template('dashboard.html', account=account,
                           username=username, recent_txns=recent_txns,
                           total_in=total_in, total_out=total_out)

@app.route('/transfer', methods=['GET'])
@login_required
def transfer():
    username = session['user']
    account  = get_account(username)
    send_log(request.remote_addr, 'page_visit',
             f'User "{account["name"]}" visited transfer page')
    recipients = {k: v for k, v in ACCOUNTS.items() if k != username}
    # Get pending transactions for this user
    user_pending = {ref: tx for ref, tx in PENDING_TRANSACTIONS.items()
                    if tx['sender_username'] == username}
    return render_template('transfer.html', account=account,
                           username=username, recipients=recipients,
                           pending_transactions=user_pending)

@app.route('/transfer', methods=['POST'])
@login_required
def transfer_post():
    username      = session['user']
    account       = get_account(username)
    ip            = request.remote_addr
    recipient_key = request.form.get('recipient', '').strip()
    amount_str    = request.form.get('amount', '0').strip()
    note          = request.form.get('note', '').strip()

    try:
        amount = float(amount_str)
    except ValueError:
        flash('Invalid amount entered.', 'danger')
        return redirect(url_for('transfer'))

    if amount <= 0:
        flash('Amount must be greater than zero.', 'danger')
        return redirect(url_for('transfer'))

    if amount > account['balance']:
        flash('Insufficient funds.', 'danger')
        send_log(ip, 'suspicious_activity',
                 f'User "{account["name"]}" attempted transfer of '
                 f'${amount:.2f} with insufficient funds')
        return redirect(url_for('transfer'))

    recipient = ACCOUNTS.get(recipient_key)
    if not recipient:
        flash('Invalid recipient.', 'danger')
        return redirect(url_for('transfer'))

    tx_id = generate_tx_id()
    now   = datetime.now().strftime('%Y-%m-%d')

    # ── LARGE TRANSFER → Send to SecureWatch for review ──────────
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

        sent = send_transaction_for_review(tx_data)

        if sent:
            # Store pending transaction locally
            PENDING_TRANSACTIONS[tx_id] = {
                'sender_username': username,
                'recipient_key':   recipient_key,
                'amount':          amount,
                'note':            note,
                'recipient_name':  recipient['name'],
                'date':            now,
            }

            # Add to transactions as pending
            TRANSACTIONS[username].append({
                'id':          tx_id,
                'type':        'debit',
                'description': f'Transfer to {recipient["name"]}'
                               + (f' — {note}' if note else ''),
                'amount':      amount,
                'date':        now,
                'status':      'under_review',
                'tx_ref':      tx_id,
            })

            send_log(ip, 'suspicious_activity',
                     f'LARGE TRANSFER FLAGGED: "{account["name"]}" '
                     f'attempted ${amount:.2f} to "{recipient["name"]}" '
                     f'— Sent to SecureWatch for review (Ref: {tx_id})')

            flash(
                f'⚠️ Your transfer of ${amount:.2f} to '
                f'{recipient["name"]} has been flagged for security '
                f'review. Reference: {tx_id}. '
                f'You will be notified once reviewed.',
                'warning'
            )
        else:
            flash('Transfer could not be processed. Please try again.', 'danger')

        return redirect(url_for('transactions'))

    # ── NORMAL TRANSFER → Process immediately ────────────────────
    ACCOUNTS[username]['balance']      -= amount
    ACCOUNTS[recipient_key]['balance'] += amount

    TRANSACTIONS[username].append({
        'id':          tx_id,
        'type':        'debit',
        'description': f'Transfer to {recipient["name"]}'
                       + (f' — {note}' if note else ''),
        'amount':      amount,
        'date':        now,
        'status':      'completed',
    })

    if recipient_key in TRANSACTIONS:
        TRANSACTIONS[recipient_key].append({
            'id':          tx_id + 'R',
            'type':        'credit',
            'description': f'Transfer from {account["name"]}'
                           + (f' — {note}' if note else ''),
            'amount':      amount,
            'date':        now,
            'status':      'completed',
        })

    send_log(ip, 'fund_transfer',
             f'Transfer: "{account["name"]}" sent ${amount:.2f} '
             f'to "{recipient["name"]}" (Ref: {tx_id})')

    flash(f'✅ Transfer of ${amount:.2f} to {recipient["name"]} '
          f'was successful! Reference: {tx_id}', 'success')
    return redirect(url_for('transactions'))


@app.route('/check-transaction-status/<tx_ref>')
@login_required
def check_transaction_status(tx_ref):
    """Check SecureWatch for transaction decision and process it."""
    username = session['user']
    account  = get_account(username)
    ip       = request.remote_addr

    status_data = get_transaction_status(tx_ref)

    if not status_data:
        flash('Could not check transaction status.', 'danger')
        return redirect(url_for('transactions'))

    status = status_data.get('status')

    # Find the transaction in local list
    user_txns = TRANSACTIONS.get(username, [])
    tx_local  = next((t for t in user_txns if t.get('tx_ref') == tx_ref), None)
    pending   = PENDING_TRANSACTIONS.get(tx_ref)

    if status == 'approved' and pending and tx_local:
        if tx_local['status'] != 'completed':
            # Process the transfer now
            recipient_key = pending['recipient_key']
            amount        = pending['amount']

            ACCOUNTS[username]['balance']      -= amount
            ACCOUNTS[recipient_key]['balance'] += amount

            # Update status
            tx_local['status'] = 'completed'

            # Add to recipient
            if recipient_key in TRANSACTIONS:
                TRANSACTIONS[recipient_key].append({
                    'id':          tx_ref + 'R',
                    'type':        'credit',
                    'description': f'Transfer from {account["name"]} '
                                   f'(Approved by Security)',
                    'amount':      amount,
                    'date':        pending['date'],
                    'status':      'completed',
                })

            # Remove from pending
            PENDING_TRANSACTIONS.pop(tx_ref, None)

            send_log(ip, 'fund_transfer',
                     f'APPROVED TRANSFER PROCESSED: '
                     f'${amount:.2f} from "{account["name"]}" '
                     f'to "{pending["recipient_name"]}" (Ref: {tx_ref})')

            flash(f'✅ Your transfer of ${amount:.2f} has been '
                  f'approved and processed!', 'success')

    elif status == 'rejected':
        if tx_local:
            tx_local['status'] = 'rejected'
        reason = status_data.get('rejection_reason', 'No reason provided')
        flash(f'🚫 Your transfer {tx_ref} was rejected. '
              f'Reason: {reason}', 'danger')

    elif status == 'document_requested':
        flash(f'📄 SecureWatch has requested a document for '
              f'transaction {tx_ref}. Please upload your approval '
              f'document below.', 'warning')

    else:
        flash(f'⏳ Transaction {tx_ref} is still under review. '
              f'Please check back later.', 'info')

    return redirect(url_for('transactions'))


@app.route('/upload-transaction-document/<tx_ref>',
           methods=['POST'])
@login_required
def upload_transaction_document(tx_ref):
    """Upload approval document for a pending transaction."""
    file = request.files.get('document')
    if not file or file.filename == '':
        flash('Please select a document to upload.', 'danger')
        return redirect(url_for('transactions'))

    try:
        r = requests.post(
            MAIN_TX_DOC_UPLOAD,
            data={'tx_ref': tx_ref},
            files={'document': (file.filename, file.stream,
                               file.content_type)},
            headers={'X-API-Key': API_KEY},
            timeout=10
        )
        if r.status_code == 200:
            flash(f'✅ Document uploaded for transaction {tx_ref}. '
                  f'SecureWatch admin will review it shortly.',
                  'success')
        else:
            flash('Document upload failed. Please try again.', 'danger')
    except Exception as e:
        flash(f'Upload error: {str(e)}', 'danger')

    return redirect(url_for('transactions'))


@app.route('/transactions')
@login_required
def transactions():
    username = session['user']
    account  = get_account(username)
    txns     = get_transactions(username)
    send_log(request.remote_addr, 'sensitive_access',
             f'User "{account["name"]}" viewed transaction history')

    # Get status updates for pending transactions
    pending_statuses = {}
    for tx in txns:
        if tx.get('status') in ['under_review', 'document_requested']:
            tx_ref = tx.get('tx_ref')
            if tx_ref:
                status_data = get_transaction_status(tx_ref)
                if status_data:
                    pending_statuses[tx_ref] = status_data

    return render_template('transactions.html',
                           account=account,
                           username=username,
                           transactions=txns[::-1],
                           pending_statuses=pending_statuses)


@app.route('/cards')
@login_required
def cards():
    username = session['user']
    account  = get_account(username)
    send_log(request.remote_addr, 'sensitive_access',
             f'User "{account["name"]}" viewed card management')
    return render_template('cards.html', account=account, username=username)

@app.route('/freeze-card', methods=['POST'])
@login_required
def freeze_card():
    username = session['user']
    account  = get_account(username)
    ACCOUNTS[username]['card_frozen'] = True
    send_log(request.remote_addr, 'card_freeze',
             f'User "{account["name"]}" FROZE their card')
    flash('🔒 Your card has been frozen.', 'success')
    return redirect(url_for('cards'))

@app.route('/unfreeze-card', methods=['POST'])
@login_required
def unfreeze_card():
    username = session['user']
    account  = get_account(username)
    ACCOUNTS[username]['card_frozen'] = False
    send_log(request.remote_addr, 'card_unfreeze',
             f'User "{account["name"]}" UNFROZE their card')
    flash('✅ Your card has been unfrozen.', 'success')
    return redirect(url_for('cards'))


@app.route('/support')
@login_required
def support():
    username = session['user']
    account  = get_account(username)
    tickets  = TICKETS.get(username, [])
    send_log(request.remote_addr, 'page_visit',
             f'User "{account["name"]}" visited support page')

    # Check for updates on existing tickets
    for ticket in tickets:
        ref    = ticket.get('ticket_ref')
        status = get_ticket_status(ref) if ref else None
        if status:
            ticket['status']      = status.get('status', ticket['status'])
            ticket['admin_reply'] = status.get('admin_reply')
            ticket['updated_at']  = status.get('updated_at')

    return render_template('support.html', account=account,
                           username=username, tickets=tickets)


@app.route('/support', methods=['POST'])
@login_required
def support_post():
    username = session['user']
    account  = get_account(username)
    ip       = request.remote_addr

    subject  = request.form.get('subject',  '').strip()
    message  = request.form.get('message',  '').strip()
    category = request.form.get('category', 'general').strip()

    if not subject or not message:
        flash('Please fill in all fields.', 'danger')
        return redirect(url_for('support'))

    ticket_ref = 'TKT' + str(random.randint(10000, 99999))
    now        = datetime.now().strftime('%Y-%m-%d %H:%M')

    # Send ticket to SecureWatch
    ticket_data = {
        'ticket_ref':  ticket_ref,
        'username':    username,
        'client_name': account['name'],
        'category':    category,
        'subject':     subject,
        'message':     message,
        'ip_address':  ip,
    }

    sent = send_ticket_to_securewatch(ticket_data)

    # Store locally
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
             f'User "{account["name"]}" raised support ticket '
             f'{ticket_ref}: "{subject}"')

    if sent:
        flash(f'✅ Ticket {ticket_ref} submitted to IT Support! '
              f'You will be notified when we respond.',
              'success')
    else:
        flash(f'✅ Ticket {ticket_ref} saved. Note: SecureWatch '
              f'connection unavailable — ticket stored locally.',
              'warning')

    return redirect(url_for('support'))


if __name__ == '__main__':
    app.run(debug=True, port=5001)
import json
import random

# ── Sample data ──────────────────────────────────────────────────
ip_addresses = [
    '192.168.1.101',
    '192.168.1.102',
    '10.0.0.55',
    '10.0.0.77',
    '172.16.0.23',
    '172.16.0.50',
    '192.168.1.200',
    '203.0.113.45',
]

sources = ['web_app', 'api', 'mobile_app']

logs = []

# ── Normal random logs ───────────────────────────────────────────
for _ in range(30):
    event = random.choice([
        'failed_login',
        'failed_login',
        'successful_login',
        'suspicious_activity',
    ])

    messages = {
        'failed_login':        'Failed login attempt - incorrect password',
        'successful_login':    'User logged in successfully',
        'suspicious_activity': 'Unusual traffic pattern detected from this IP',
    }

    logs.append({
        'ip_address': random.choice(ip_addresses),
        'event_type': event,
        'message':    messages[event],
        'source':     random.choice(sources),
    })

# ── Brute force simulation ───────────────────────────────────────
# 6 failed logins from same IP → triggers Brute Force Alert
for _ in range(6):
    logs.append({
        'ip_address': '10.10.10.99',
        'event_type': 'failed_login',
        'message':    'Failed login attempt - brute force simulation',
        'source':     'web_app',
    })

# ── Suspicious activity simulation ──────────────────────────────
for _ in range(2):
    logs.append({
        'ip_address': '172.16.99.99',
        'event_type': 'suspicious_activity',
        'message':    'Unusual traffic pattern detected from this IP',
        'source':     'api',
    })

# ── Save file ────────────────────────────────────────────────────
filename = 'test_logs.json'
with open(filename, 'w') as f:
    json.dump(logs, f, indent=2)

print(f'✅ Generated {len(logs)} log entries')
print(f'📁 Saved to: {filename}')
print(f'')
print(f'Expected alerts after upload:')
print(f'  🚨 Brute Force Attack   — from 10.10.10.99')
print(f'  ⚠️  Suspicious Activity  — from 172.16.99.99')
print(f'')
print(f'Now upload test_logs.json on the Logs page.')
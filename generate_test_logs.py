import json
import random
from datetime import datetime

# ── Sample data pools ────────────────────────────────────────────
ip_addresses = [
    '192.168.1.101',
    '192.168.1.102',
    '10.0.0.55',
    '10.0.0.77',
    '172.16.0.23',
    '172.16.0.50',
    '192.168.1.200',
    '203.0.113.45',
    '198.51.100.22',
    '192.0.2.18',
]

event_types = [
    'failed_login',
    'failed_login',       # duplicated to make it more frequent
    'failed_login',
    'successful_login',
    'suspicious_activity',
]

messages = {
    'failed_login':        'Failed login attempt - incorrect password',
    'successful_login':    'User logged in successfully',
    'suspicious_activity': 'Unusual traffic pattern detected from this IP',
}

sources = ['web_app', 'api', 'mobile_app']

# ── Generate logs ────────────────────────────────────────────────
logs = []

for _ in range(50):                          # generates 50 log entries
    event = random.choice(event_types)
    logs.append({
        'ip_address':  random.choice(ip_addresses),
        'event_type':  event,
        'message':     messages[event],
        'source':      random.choice(sources),
    })

# ── Add a brute force simulation ─────────────────────────────────
# Same IP, 6 failed logins in a row — should trigger an alert
for _ in range(6):
    logs.append({
        'ip_address': '10.10.10.99',
        'event_type': 'failed_login',
        'message':    'Failed login attempt - brute force simulation',
        'source':     'web_app',
    })

# ── Save to JSON file ────────────────────────────────────────────
filename = 'test_logs.json'
with open(filename, 'w') as f:
    json.dump(logs, f, indent=2)

print(f'✅ Generated {len(logs)} log entries')
print(f'📁 Saved to: {filename}')
print(f'')
print(f'Now upload test_logs.json using the Upload Log File button')
print(f'on the Logs page of your dashboard.')
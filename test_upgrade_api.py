#!/usr/bin/env python
"""Test the /upgrade endpoint"""
import requests
import json

data = {
    'message_id': 'test-msg-123',
    'recipient_email': 'angeleo.angelei@gmail.com'
}

print('Sending:', json.dumps(data, indent=2))
resp = requests.post('http://localhost:8000/upgrade', json=data)
print('Status:', resp.status_code)
print('Response:', resp.text)

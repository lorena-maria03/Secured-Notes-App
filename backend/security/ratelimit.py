from datetime import datetime, timedelta
from typing import Dict

login_attempts: Dict[str, list] = {}

MAX_ATTEMPTS = 5
WINDOW_MINUTES = 15
LOCKOUT_MINUTES = 30

def is_rate_limited(ip: str) -> bool:
    now = datetime.utcnow()
    window_start = now - timedelta(minutes=WINDOW_MINUTES)

    if ip not in login_attempts:
        return False

    login_attempts[ip] = [t for t in login_attempts[ip] if t > window_start]

    if len(login_attempts[ip]) >= MAX_ATTEMPTS:
        return True

    return False

def record_attempt(ip: str):
    now = datetime.utcnow()
    if ip not in login_attempts:
        login_attempts[ip] = []
    login_attempts[ip].append(now)

def clear_attempts(ip: str):
    if ip in login_attempts:
        login_attempts[ip] = []
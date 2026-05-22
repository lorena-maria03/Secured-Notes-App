from datetime import datetime, timedelta
from typing import Dict, Optional

login_attempts: Dict[str, list] = {}
locked_until: Dict[str, datetime] = {}

MAX_ATTEMPTS = 5
WINDOW_MINUTES = 15
LOCKOUT_MINUTES = 30


def is_rate_limited(ip: str) -> bool:
    now = datetime.utcnow()

    expiry = locked_until.get(ip)
    if expiry:
        if now < expiry:
            return True
        del locked_until[ip]

    if ip not in login_attempts:
        return False

    window_start = now - timedelta(minutes=WINDOW_MINUTES)
    login_attempts[ip] = [t for t in login_attempts[ip] if t > window_start]

    return len(login_attempts[ip]) >= MAX_ATTEMPTS


def record_attempt(ip: str):
    now = datetime.utcnow()
    if ip not in login_attempts:
        login_attempts[ip] = []
    login_attempts[ip].append(now)

    window_start = now - timedelta(minutes=WINDOW_MINUTES)
    login_attempts[ip] = [t for t in login_attempts[ip] if t > window_start]
    if len(login_attempts[ip]) >= MAX_ATTEMPTS:
        locked_until[ip] = now + timedelta(minutes=LOCKOUT_MINUTES)


def clear_attempts(ip: str):
    login_attempts.pop(ip, None)
    locked_until.pop(ip, None)

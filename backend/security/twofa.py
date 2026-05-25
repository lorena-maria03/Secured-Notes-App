import random
import string
import io
import base64
import secrets
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from typing import Optional
from dotenv import load_dotenv
import os
import pyotp
import qrcode

load_dotenv()

SMTP_HOST = os.getenv("SMTP_HOST", "localhost")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL", "noreply@securednotes.local")
OTP_EXPIRE_MINUTES = 10


def _send_email(to: str, subject: str, html: str) -> bool:
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM_EMAIL
    msg["To"] = to
    msg.attach(MIMEText(html, "html"))
    try:
        if SMTP_PORT == 465:
            ctx = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT)
        else:
            ctx = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
        with ctx as smtp:
            smtp.ehlo()
            if SMTP_PORT == 587:
                smtp.starttls()
                smtp.ehlo()
            if SMTP_USER and SMTP_PASSWORD:
                smtp.login(SMTP_USER, SMTP_PASSWORD)
            smtp.sendmail(SMTP_FROM_EMAIL, [to], msg.as_string())
        return True
    except Exception as e:
        print(f"[SMTP] Error sending to {to}: {e}")
        return False

otp_store: dict = {}

def generate_otp(email: str) -> bool:
    code = ''.join(random.choices(string.digits, k=6))
    expires = datetime.utcnow() + timedelta(minutes=OTP_EXPIRE_MINUTES)
    otp_store[email] = {"code": code, "expires": expires}

    print(f"[2FA] Code for {email}: {code}")

    return _send_email(
        to=email,
        subject="Your verification code - Secured Notes",
        html=f"""
            <h2>Your verification code</h2>
            <p>Use the code below to sign in:</p>
            <h1 style="letter-spacing: 8px; color: #4F46E5;">{code}</h1>
            <p>This code expires in {OTP_EXPIRE_MINUTES} minutes.</p>
            <p>If you did not request this code, ignore this email.</p>
        """
    )

def verify_otp(email: str, code: str) -> bool:
    if email not in otp_store:
        return False

    stored = otp_store[email]

    if datetime.utcnow() > stored["expires"]:
        del otp_store[email]
        return False

    if stored["code"] != code:
        return False

    del otp_store[email]
    return True

def get_otp_time_left(email: str) -> Optional[int]:
    if email not in otp_store:
        return None
    seconds_left = (otp_store[email]["expires"] - datetime.utcnow()).total_seconds()
    return max(0, int(seconds_left))


# -- Pending login store (gates the email-fallback endpoint) --
# Populated when a TOTP user passes password check. Expires in 5 minutes.

pending_logins: dict = {}
PENDING_TTL_MINUTES = 5


def record_pending_login(email: str):
    pending_logins[email] = datetime.utcnow() + timedelta(minutes=PENDING_TTL_MINUTES)


def is_pending_login(email: str) -> bool:
    expires = pending_logins.get(email)
    if not expires:
        return False
    if datetime.utcnow() > expires:
        del pending_logins[email]
        return False
    return True


# -- Per-email reset send cooldown (prevents inbox flooding from multiple IPs) --

reset_send_times: dict = {}
RESET_EMAIL_COOLDOWN_SECONDS = 60


def can_send_reset_email(email: str) -> bool:
    next_allowed = reset_send_times.get(email)
    return not next_allowed or datetime.utcnow() >= next_allowed


def record_reset_email_sent(email: str):
    reset_send_times[email] = datetime.utcnow() + timedelta(seconds=RESET_EMAIL_COOLDOWN_SECONDS)


# -- Password reset tokens --

reset_store: dict = {}
RESET_TTL_MINUTES = 15


def generate_reset_token(email: str) -> str:
    token = secrets.token_urlsafe(32)
    reset_store[token] = {
        "email": email,
        "expires": datetime.utcnow() + timedelta(minutes=RESET_TTL_MINUTES)
    }
    return token


def consume_reset_token(token: str) -> Optional[str]:
    entry = reset_store.get(token)
    if not entry:
        return None
    if datetime.utcnow() > entry["expires"]:
        del reset_store[token]
        return None
    del reset_store[token]
    return entry["email"]


def send_reset_email(email: str, token: str, base_url: str) -> bool:
    reset_link = f"{base_url}?reset={token}"
    print(f"[RESET] Link for {email}: {reset_link}")
    return _send_email(
        to=email,
        subject="Reset your password - Secured Notes",
        html=f"""
            <h2>Reset your password</h2>
            <p>Click the link below to set a new password. This link expires in {RESET_TTL_MINUTES} minutes.</p>
            <p><a href="{reset_link}" style="color:#4F46E5;">Reset my password</a></p>
            <p>If you did not request this, ignore this email.</p>
        """
    )


# -- TOTP (Authenticator app) --

def generate_totp_secret() -> str:
    return pyotp.random_base32()


def generate_totp_qr_base64(secret: str, email: str) -> str:
    uri = pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name="Secured Notes")
    qr = qrcode.QRCode(box_size=8, border=4)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode()


def verify_totp_code(secret: str, code: str) -> bool:
    # valid_window=1 allows 30 seconds of clock drift in either direction
    return pyotp.TOTP(secret).verify(code, valid_window=1)

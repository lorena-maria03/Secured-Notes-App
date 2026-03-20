import random
import string
from datetime import datetime, timedelta
from typing import Optional
import sendgrid
from sendgrid.helpers.mail import Mail
from dotenv import load_dotenv
import os

load_dotenv()

SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
SENDGRID_FROM_EMAIL = os.getenv("SENDGRID_FROM_EMAIL")
OTP_EXPIRE_MINUTES = 10

otp_store: dict = {}

def generate_otp(email: str) -> bool:
    code = ''.join(random.choices(string.digits, k=6))
    expires = datetime.utcnow() + timedelta(minutes=OTP_EXPIRE_MINUTES)
    otp_store[email] = {"code": code, "expires": expires}

    message = Mail(
        from_email=SENDGRID_FROM_EMAIL,
        to_emails=email,
        subject="Your verification code - Secured Notes",
        html_content=f"""
            <h2>Your verification code</h2>
            <p>Use the code below to sign in:</p>
            <h1 style="letter-spacing: 8px; color: #4F46E5;">{code}</h1>
            <p>This code expires in {OTP_EXPIRE_MINUTES} minutes.</p>
            <p>If you did not request this code, ignore this email.</p>
        """
    )

    try:
        sg = sendgrid.SendGridAPIClient(api_key=SENDGRID_API_KEY)
        sg.send(message)
        return True
    except Exception as e:
        print(f"SendGrid error: {e}")
        return False

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
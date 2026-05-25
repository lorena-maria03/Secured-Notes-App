from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr, validator
import time

from database import get_db
from models import User, UserKey
from security.hashing import hash_password, verify_password
from security.jwt import create_token
from security.twofa import generate_otp, verify_otp, generate_totp_secret, generate_totp_qr_base64, verify_totp_code, record_pending_login, is_pending_login, generate_reset_token, consume_reset_token, send_reset_email, can_send_reset_email, record_reset_email_sent
from security.crypto import generate_rsa_keypair
from security.ratelimit import is_rate_limited, record_attempt, clear_attempts
from dependencies import get_current_user_id

router = APIRouter()


class RegisterSchema(BaseModel):
    email: EmailStr
    username: str
    password: str

    @validator('username')
    def username_valid(cls, v):
        if len(v) < 3:
            raise ValueError('Username must be at least 3 characters')
        return v


class LoginSchema(BaseModel):
    email: EmailStr
    password: str


class VerifyOTPSchema(BaseModel):
    email: EmailStr
    code: str


class RequestEmailOTPSchema(BaseModel):
    email: EmailStr


class ForgotPasswordSchema(BaseModel):
    email: EmailStr


class ResetPasswordSchema(BaseModel):
    token: str
    new_password: str


class TOTPConfirmSchema(BaseModel):
    secret: str
    code: str


class TOTPVerifySchema(BaseModel):
    email: EmailStr
    code: str


class TOTPDisableSchema(BaseModel):
    code: str


def _validate_password(p: str) -> None:
    if len(p) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    if not any(c.isupper() for c in p):
        raise HTTPException(status_code=400, detail="Password must contain at least one uppercase letter")
    if not any(c.islower() for c in p):
        raise HTTPException(status_code=400, detail="Password must contain at least one lowercase letter")
    if not any(c.isdigit() for c in p):
        raise HTTPException(status_code=400, detail="Password must contain at least one number")


@router.post("/register")
def register(data: RegisterSchema, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    if db.query(User).filter(User.username == data.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")

    _validate_password(data.password)

    start = time.time()
    hashed = hash_password(data.password)
    print(f"[TIMING] bcrypt hashing: {(time.time()-start)*1000:.2f}ms")

    user = User(
        email=data.email,
        username=data.username,
        hashed_password=hashed
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    start = time.time()
    public_key, private_key = generate_rsa_keypair()
    print(f"[TIMING] RSA key generation: {(time.time()-start)*1000:.2f}ms")

    user_key = UserKey(
        user_id=user.id,
        public_key=public_key,
        private_key_enc=private_key
    )
    db.add(user_key)
    db.commit()

    return {"message": "Account created successfully", "user_id": user.id}


@router.post("/login")
def login(data: LoginSchema, request: Request, db: Session = Depends(get_db)):
    ip = request.client.host

    if is_rate_limited(ip):
        raise HTTPException(status_code=429, detail="Too many attempts. Try again later.")

    user = db.query(User).filter(User.email == data.email).first()

    start = time.time()
    valid = user and verify_password(data.password, user.hashed_password)
    print(f"[TIMING] bcrypt verify: {(time.time()-start)*1000:.2f}ms")

    if not valid:
        record_attempt(ip)
        raise HTTPException(status_code=401, detail="Invalid email or password")

    clear_attempts(ip)

    if user.two_factor_enabled:
        record_pending_login(data.email)
        return {"requires_totp": True, "email": data.email}

    generate_otp(data.email)
    return {"requires_2fa": True, "email": data.email}


@router.post("/verify-2fa")
def verify_2fa(data: VerifyOTPSchema, request: Request, db: Session = Depends(get_db)):
    ip = request.client.host
    if is_rate_limited(ip):
        raise HTTPException(status_code=429, detail="Too many attempts. Try again later.")

    if not verify_otp(data.email, data.code):
        record_attempt(ip)
        raise HTTPException(status_code=401, detail="Invalid or expired code")

    user = db.query(User).filter(User.email == data.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    clear_attempts(ip)
    token = create_token({"sub": str(user.id), "pv": user.password_version})
    return {"access_token": token}


@router.post("/forgot-password")
def forgot_password(data: ForgotPasswordSchema, request: Request, db: Session = Depends(get_db)):
    ip = request.client.host
    if is_rate_limited(ip):
        raise HTTPException(status_code=429, detail="Too many attempts. Try again later.")

    record_attempt(ip)  # counted on every call since each may fire an email

    user = db.query(User).filter(User.email == data.email).first()
    if user and can_send_reset_email(data.email):
        token = generate_reset_token(data.email)
        base_url = str(request.base_url) + "index.html"
        send_reset_email(data.email, token, base_url)
        record_reset_email_sent(data.email)
    return {"message": "If that email exists, a reset link has been sent"}


@router.post("/reset-password")
def reset_password(data: ResetPasswordSchema, db: Session = Depends(get_db)):
    email = consume_reset_token(data.token)
    if not email:
        raise HTTPException(status_code=400, detail="Invalid or expired reset link")

    _validate_password(data.new_password)

    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.hashed_password = hash_password(data.new_password)
    user.password_version += 1
    db.commit()
    return {"message": "Password updated successfully"}


@router.post("/request-email-otp")
def request_email_otp(data: RequestEmailOTPSchema, request: Request):
    ip = request.client.host
    if is_rate_limited(ip):
        raise HTTPException(status_code=429, detail="Too many attempts. Try again later.")
    if not is_pending_login(data.email):
        raise HTTPException(status_code=403, detail="No active login session for this email")
    generate_otp(data.email)
    return {"message": "Verification code sent to your email"}


@router.get("/me")
def me(user_id: int = Depends(get_current_user_id), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"id": user.id, "email": user.email, "username": user.username, "two_factor_enabled": user.two_factor_enabled}


# ── TOTP endpoints ────────────────────────────────────────────────────────────

@router.post("/totp/setup")
def totp_setup(user_id: int = Depends(get_current_user_id), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    secret = generate_totp_secret()
    qr_base64 = generate_totp_qr_base64(secret, user.email)
    return {"secret": secret, "qr": qr_base64}


@router.post("/totp/confirm")
def totp_confirm(data: TOTPConfirmSchema, user_id: int = Depends(get_current_user_id), db: Session = Depends(get_db)):
    if not verify_totp_code(data.secret, data.code):
        raise HTTPException(status_code=400, detail="Invalid code — make sure the code is current and try again")

    user = db.query(User).filter(User.id == user_id).first()
    user_key = db.query(UserKey).filter(UserKey.user_id == user_id).first()
    if not user or not user_key:
        raise HTTPException(status_code=404, detail="User not found")

    user_key.two_factor_secret = data.secret
    user.two_factor_enabled = True
    db.commit()

    return {"message": "Authenticator app enabled successfully"}


@router.post("/totp/verify")
def totp_verify(data: TOTPVerifySchema, request: Request, db: Session = Depends(get_db)):
    ip = request.client.host
    if is_rate_limited(ip):
        raise HTTPException(status_code=429, detail="Too many attempts. Try again later.")

    if not is_pending_login(data.email):
        record_attempt(ip)
        raise HTTPException(status_code=403, detail="No active login session for this email")

    user = db.query(User).filter(User.email == data.email).first()
    if not user or not user.two_factor_enabled:
        record_attempt(ip)
        raise HTTPException(status_code=400, detail="TOTP not enabled for this account")

    user_key = db.query(UserKey).filter(UserKey.user_id == user.id).first()
    if not user_key or not user_key.two_factor_secret:
        raise HTTPException(status_code=500, detail="TOTP secret missing")

    if not verify_totp_code(user_key.two_factor_secret, data.code):
        record_attempt(ip)
        raise HTTPException(status_code=401, detail="Invalid or expired code")

    clear_attempts(ip)
    token = create_token({"sub": str(user.id), "pv": user.password_version})
    return {"access_token": token}


@router.post("/totp/disable")
def totp_disable(data: TOTPDisableSchema, user_id: int = Depends(get_current_user_id), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    user_key = db.query(UserKey).filter(UserKey.user_id == user_id).first()

    if not user or not user_key:
        raise HTTPException(status_code=404, detail="User not found")

    if not user.two_factor_enabled or not user_key.two_factor_secret:
        raise HTTPException(status_code=400, detail="TOTP is not enabled")

    if not verify_totp_code(user_key.two_factor_secret, data.code):
        raise HTTPException(status_code=401, detail="Invalid code")

    user.two_factor_enabled = False
    user_key.two_factor_secret = None
    db.commit()

    return {"message": "Authenticator app disabled"}
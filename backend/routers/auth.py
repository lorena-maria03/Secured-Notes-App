from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr, validator
import time

from database import get_db
from models import User, UserKey
from security.hashing import hash_password, verify_password
from security.jwt import create_token, get_user_id_from_token
from security.twofa import generate_otp, verify_otp
from security.crypto import generate_rsa_keypair
from security.ratelimit import is_rate_limited, record_attempt, clear_attempts

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


def get_current_user_id(request: Request) -> int:
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        raise HTTPException(status_code=401, detail="Token missing")
    user_id = get_user_id_from_token(token)
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token")
    return int(user_id)


@router.post("/register")
def register(data: RegisterSchema, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    if db.query(User).filter(User.username == data.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")

    p = data.password
    if len(p) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    if not any(c.isupper() for c in p):
        raise HTTPException(status_code=400, detail="Password must contain at least one uppercase letter")
    if not any(c.islower() for c in p):
        raise HTTPException(status_code=400, detail="Password must contain at least one lowercase letter")
    if not any(c.isdigit() for c in p):
        raise HTTPException(status_code=400, detail="Password must contain at least one number")

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
    generate_otp(data.email)

    return {"requires_2fa": True, "email": data.email}


@router.post("/verify-2fa")
def verify_2fa(data: VerifyOTPSchema, db: Session = Depends(get_db)):
    if not verify_otp(data.email, data.code):
        raise HTTPException(status_code=401, detail="Invalid or expired code")

    user = db.query(User).filter(User.email == data.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    token = create_token({"sub": str(user.id)})
    return {"access_token": token}


@router.get("/me")
def me(request: Request, db: Session = Depends(get_db)):
    user_id = get_current_user_id(request)
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"id": user.id, "email": user.email, "username": user.username}
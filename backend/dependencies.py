from fastapi import HTTPException, Request, Depends
from sqlalchemy.orm import Session

from database import get_db
from models import User
from security.jwt import decode_token


def get_current_user_id(request: Request, db: Session = Depends(get_db)) -> int:
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        raise HTTPException(status_code=401, detail="Token missing")

    payload = decode_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")

    try:
        user_id = int(payload["sub"])
    except (KeyError, ValueError, TypeError):
        raise HTTPException(status_code=401, detail="Invalid token")

    token_pv = payload.get("pv", 0)
    user = db.query(User).filter(User.id == user_id).first()
    if not user or user.password_version != token_pv:
        raise HTTPException(status_code=401, detail="Session expired — please log in again")

    return user_id

from fastapi import HTTPException, Request
from security.jwt import get_user_id_from_token


def get_current_user_id(request: Request) -> int:
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        raise HTTPException(status_code=401, detail="Token missing")
    user_id = get_user_id_from_token(token)
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token")
    return int(user_id)

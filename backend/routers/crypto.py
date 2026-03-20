from fastapi import APIRouter, UploadFile, File, HTTPException, Request
from pydantic import BaseModel

from security.stego import hide_message_in_image, extract_message_from_image
from security.jwt import get_user_id_from_token

router = APIRouter()

# ------------ Schemas

class SQLCheckSchema(BaseModel):
    input_text: str

# ---------------- Helper

def get_current_user_id(request: Request) -> int:
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        raise HTTPException(status_code=401, detail="Missing token")
    user_id = get_user_id_from_token(token)
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token")
    return int(user_id)

# ------------- SQL Injection checker

SQL_PATTERNS = [
    "--", ";--", ";", "/*", "*/", "xp_",
    "SELECT", "DROP", "INSERT", "UPDATE",
    "DELETE", "UNION", "OR 1=1", "' OR '",
    "1=1", "OR TRUE", "SLEEP(", "BENCHMARK("
]

@router.post("/check-sql")
def check_sql_injection(data: SQLCheckSchema, request: Request):
    get_current_user_id(request)

    input_upper = data.input_text.upper()
    found = [p for p in SQL_PATTERNS if p.upper() in input_upper]

    if found:
        return {
            "safe": False,
            "message": "SQL injection detected!",
            "patterns_found": found
        }
    return {"safe": True, "message": "Safe input"}

# ------------------ Steganografie

@router.post("/stego/hide")
async def hide_message(
    request: Request,
    message: str,
    image: UploadFile = File(...)
):
    get_current_user_id(request)

    if not image.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="File must be an image")

    image_bytes = await image.read()

    try:
        result_bytes = hide_message_in_image(image_bytes, message)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    from fastapi.responses import Response
    return Response(
        content=result_bytes,
        media_type="image/png",
        headers={"Content-Disposition": "attachment; filename=stego_image.png"}
    )

@router.post("/stego/extract")
async def extract_message(
    request: Request,
    image: UploadFile = File(...)
):
    get_current_user_id(request)

    if not image.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="File must be an image")

    image_bytes = await image.read()

    try:
        message = extract_message_from_image(image_bytes)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error at extraction: {str(e)}")

    return {"message": message}
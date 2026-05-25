from fastapi import APIRouter, Depends, UploadFile, File, HTTPException
from pydantic import BaseModel

from security.stego import hide_message_in_image, extract_message_from_image
from dependencies import get_current_user_id

router = APIRouter()


class SQLCheckSchema(BaseModel):
    input_text: str


# ------------- SQL Injection checker

SQL_PATTERNS = [
    "--", ";--", ";", "/*", "*/", "xp_",
    "SELECT", "DROP", "INSERT", "UPDATE", "DELETE",
    "UNION", "TRUNCATE", "EXEC", "EXECUTE", "DECLARE",
    "OR 1=1", "AND 1=1", "AND 1=2", "OR 1=2",
    "' OR '", "1=1", "OR TRUE", "AND TRUE",
    "SLEEP(", "BENCHMARK(", "WAITFOR",
    "CAST(", "CONVERT(", "CHAR(", "HEX(",
    "@@", "INFORMATION_SCHEMA",
]

_DISCLAIMER = (
    "Pattern-based detection only — does not catch all injection techniques "
    "(e.g. inline comments, hex encoding, second-order injection)."
)

@router.post("/check-sql")
def check_sql_injection(data: SQLCheckSchema, _: int = Depends(get_current_user_id)):
    input_upper = data.input_text.upper()
    found = [p for p in SQL_PATTERNS if p.upper() in input_upper]

    if found:
        return {
            "safe": False,
            "message": "SQL injection patterns detected.",
            "patterns_found": found,
            "disclaimer": _DISCLAIMER,
        }
    return {"safe": True, "message": "No known patterns detected.", "disclaimer": _DISCLAIMER}

# ------------------ Steganografie

@router.post("/stego/hide")
async def hide_message(
    message: str,
    image: UploadFile = File(...),
    _: int = Depends(get_current_user_id),
):

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
    image: UploadFile = File(...),
    _: int = Depends(get_current_user_id),
):

    if not image.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="File must be an image")

    image_bytes = await image.read()

    try:
        message = extract_message_from_image(image_bytes)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error at extraction: {str(e)}")

    return {"message": message}
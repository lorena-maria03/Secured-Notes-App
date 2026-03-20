from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel

from database import get_db
from models import Note, NoteKey, UserKey
from security.crypto import (
    generate_aes_key, encrypt_aes, decrypt_aes,
    encrypt_with_rsa, decrypt_with_rsa,
    sign_note, verify_signature
)
from security.jwt import get_user_id_from_token

router = APIRouter()


class NoteCreate(BaseModel):
    title: str
    content: str


def get_current_user_id(request: Request) -> int:
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        raise HTTPException(status_code=401, detail="Token missing")
    user_id = get_user_id_from_token(token)
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token")
    return int(user_id)


@router.post("/")
def create_note(data: NoteCreate, request: Request, db: Session = Depends(get_db)):
    user_id = get_current_user_id(request)

    user_key = db.query(UserKey).filter(UserKey.user_id == user_id).first()
    if not user_key:
        raise HTTPException(status_code=404, detail="User keys not found")

    aes_key = generate_aes_key()
    encrypted_content, iv = encrypt_aes(data.content, aes_key)
    encrypted_aes_key = encrypt_with_rsa(aes_key, user_key.public_key)
    signature = sign_note(data.content, user_key.private_key_enc)

    note = Note(
        owner_id=user_id,
        title=data.title,
        content_encrypted=encrypted_content,
        content_iv=iv,
        signature=signature
    )
    db.add(note)
    db.commit()
    db.refresh(note)

    note_key = NoteKey(
        note_id=note.id,
        encrypted_aes_key=encrypted_aes_key
    )
    db.add(note_key)
    db.commit()

    return {"message": "Note created", "note_id": note.id}


@router.put("/{note_id}")
def update_note(note_id: int, data: NoteCreate, request: Request, db: Session = Depends(get_db)):
    user_id = get_current_user_id(request)

    user_key = db.query(UserKey).filter(UserKey.user_id == user_id).first()
    if not user_key:
        raise HTTPException(status_code=404, detail="User keys not found")

    note = db.query(Note).filter(Note.id == note_id, Note.owner_id == user_id).first()
    if not note:
        raise HTTPException(status_code=404, detail="Note not found")

    aes_key = generate_aes_key()
    encrypted_content, iv = encrypt_aes(data.content, aes_key)
    encrypted_aes_key = encrypt_with_rsa(aes_key, user_key.public_key)
    signature = sign_note(data.content, user_key.private_key_enc)

    note.title = data.title
    note.content_encrypted = encrypted_content
    note.content_iv = iv
    note.signature = signature

    note_key = db.query(NoteKey).filter(NoteKey.note_id == note_id).first()
    if note_key:
        note_key.encrypted_aes_key = encrypted_aes_key
    else:
        db.add(NoteKey(note_id=note_id, encrypted_aes_key=encrypted_aes_key))

    db.commit()
    return {"message": "Note updated", "note_id": note.id}


@router.get("/")
def get_notes(request: Request, db: Session = Depends(get_db)):
    user_id = get_current_user_id(request)
    notes = db.query(Note).filter(Note.owner_id == user_id).all()
    return [
        {
            "id": n.id,
            "title": n.title,
            "created_at": n.created_at
        }
        for n in notes
    ]


@router.get("/{note_id}")
def get_note(note_id: int, request: Request, db: Session = Depends(get_db)):
    user_id = get_current_user_id(request)

    note = db.query(Note).filter(Note.id == note_id, Note.owner_id == user_id).first()
    if not note:
        raise HTTPException(status_code=404, detail="Note not found")

    user_key = db.query(UserKey).filter(UserKey.user_id == user_id).first()
    if not user_key:
        raise HTTPException(status_code=404, detail="User keys not found")

    note_key = db.query(NoteKey).filter(NoteKey.note_id == note_id).first()
    if not note_key:
        raise HTTPException(status_code=404, detail="Note key not found")

    aes_key = decrypt_with_rsa(note_key.encrypted_aes_key, user_key.private_key_enc)
    content = decrypt_aes(note.content_encrypted, aes_key, note.content_iv)
    is_valid = verify_signature(content, note.signature, user_key.public_key)

    return {
        "id": note.id,
        "title": note.title,
        "content": content,
        "signature_valid": is_valid,
        "created_at": note.created_at
    }


@router.delete("/{note_id}")
def delete_note(note_id: int, request: Request, db: Session = Depends(get_db)):
    user_id = get_current_user_id(request)

    note = db.query(Note).filter(Note.id == note_id, Note.owner_id == user_id).first()
    if not note:
        raise HTTPException(status_code=404, detail="Note not found")

    db.query(NoteKey).filter(NoteKey.note_id == note_id).delete()
    db.delete(note)
    db.commit()

    return {"message": "Note deleted"}
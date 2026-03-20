from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv
import os

from database import engine, Base
from routers import auth, notes, crypto

load_dotenv()

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Secured Notes App")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/auth", tags=["auth"])
app.include_router(notes.router, prefix="/notes", tags=["notes"])
app.include_router(crypto.router, prefix="/crypto", tags=["crypto"])

app.mount("/", StaticFiles(directory="../frontend", html=True), name="frontend")

@app.get("/health")
def health_check():
    return {"status": "ok", "message": "Secured Notes API running"}
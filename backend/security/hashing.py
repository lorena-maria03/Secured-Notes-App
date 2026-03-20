import bcrypt
import os

PEPPER = os.getenv("PASSWORD_PEPPER", "default_pepper_schimba_asta")

def hash_password(password: str) -> str:
    # add pepper + random salt generated de bcrypt
    peppered = password + PEPPER
    salt = bcrypt.gensalt(rounds=12) # 12 rounds
    hashed = bcrypt.hashpw(peppered.encode("utf-8"), salt)
    return hashed.decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    peppered = plain_password + PEPPER
    return bcrypt.checkpw(
        peppered.encode("utf-8"),
        hashed_password.encode("utf-8")
    )
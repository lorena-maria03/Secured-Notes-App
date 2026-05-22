import bcrypt
import os

PEPPER = os.getenv("PASSWORD_PEPPER", "default_pepper_schimba_asta")

BCRYPT_ROUNDS = 12


def hash_password(password: str) -> str:
    peppered = password + PEPPER
    hashed = bcrypt.hashpw(peppered.encode("utf-8"), bcrypt.gensalt(rounds=BCRYPT_ROUNDS))
    return hashed.decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    peppered = plain_password + PEPPER
    return bcrypt.checkpw(
        peppered.encode("utf-8"),
        hashed_password.encode("utf-8")
    )
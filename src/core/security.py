from datetime import datetime, timedelta
from typing import Any
from jose import jwt
from src.core.config import get_settings
from passlib.context import CryptContext

settings = get_settings()

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


def create_access_token(data: dict[str, Any]):
    to_encode = data.copy()
    expire = datetime.now() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    expire = datetime.now() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def create_refresh_token(data: dict[str, Any]):
    to_encode = data.copy()
    expire = datetime.now() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    expire = datetime.now() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

# Rename functions for consistency
def get_password_hash(password: str) -> str:
    """Generate a hashed password"""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify if a plain password matches the hashed password"""
    return pwd_context.verify(plain_password, hashed_password)

# Keep old function names for backward compatibility
encrypt_password = get_password_hash
check_encrypted_password = verify_password

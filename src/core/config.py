
from pydantic_settings import BaseSettings
from functools import lru_cache

class Settings(BaseSettings):
    DATABASE_URL: str = "sqlite:///database.db"
    ENVIRONMENT: str = "development"  # Options: development, production, testing
    REDIS_DATABASE_HOST: str = 'redist-host'
    REDIS_PORT: int =  18607
    REDIS_PASSWORD: str =  "your-redis-password"
    REDIS_USERNAME: str =  'default'
    SECRET_KEY: str = "your-secret-key"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    ALGORITHM: str = "HS256"
    DEBUG: bool = True



    # Mail Configurations
    GMAIL_USERNAME: str = ""
    GMAIL_APP_PASSWORD: str = ""
    GMAIL_SENDER_NAME: str = "Tana F.G Ivan"
    GMAIL_ACCOUNT: str = ""



    # class Config:
    #     env_file = ".auth.env"
    #     env_file_encoding = "utf-8"

@lru_cache
def get_settings():
    return Settings()

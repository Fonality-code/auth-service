import redis
from src.core.config import get_settings

settings = get_settings()


r_database = redis.Redis(
    host=settings.REDIS_DATABASE_HOST,
    port=settings.REDIS_PORT,
    decode_responses=True,
    username=settings.REDIS_USERNAME,
    password=settings.REDIS_PASSWORD
)

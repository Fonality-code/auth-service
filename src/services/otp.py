import json
import random
import string
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Protocol
from pydantic import ValidationError
from redis import Redis
from src.core.redis import r_database
from src.schemas.user import User, UserCreate, UserData
from functools import lru_cache
from threading import Lock
from src.utils.exceptions import OTPServiceError, RateLimitExceeded, MaxRetriesExceeded


class EmailProvider(Protocol):
    """Protocol for objects that provide an email field"""
    email: str


class OTPService:
    def __init__(self, redis_client: Redis):
        self.redis = redis_client
        self.otp_ttl = 300  # OTP expires in 5 minutes
        self.user_ttl = 3600  # User data expires in 1 hour
        self.max_attempts = 3  # Maximum OTP verification attempts
        self.max_resends = 5  # Maximum resend attempts per hour
        self.lockout_duration = 900  # 15 minutes lockout after max attempts
        self.rate_limit_window = 3600  # 1 hour window for rate limiting
        self._locks: Dict[str, Lock] = {}
        self._lock_creation_lock = Lock()

    def _get_user_lock(self, email: str) -> Lock:
        """Get or create a lock for a specific user email."""
        with self._lock_creation_lock:
            if email not in self._locks:
                self._locks[email] = Lock()
            return self._locks[email]

    def generate_otp(self, length: int = 6) -> str:
        """Generate a random OTP code"""
        return ''.join(random.choices(string.digits, k=length))

    def _get_attempt_key(self, email: str) -> str:
        """Get Redis key for tracking verification attempts."""
        return f"otp_attempts:{email}"

    def _get_resend_key(self, email: str) -> str:
        """Get Redis key for tracking resend attempts."""
        return f"otp_resend:{email}"

    def _get_lockout_key(self, email: str) -> str:
        """Get Redis key for user lockout."""
        return f"otp_lockout:{email}"

    def _get_rate_limit_key(self, email: str) -> str:
        """Get Redis key for rate limiting OTP generation."""
        return f"otp_rate_limit:{email}"

    def _is_locked_out(self, email: str) -> bool:
        """Check if user is currently locked out."""
        lockout_key = self._get_lockout_key(email)
        result = self.redis.exists(lockout_key)
        return bool(result)

    def _check_rate_limit(self, email: str) -> bool:
        """Check if user has exceeded rate limit for OTP generation."""
        rate_limit_key = self._get_rate_limit_key(email)
        current_count = self.redis.get(rate_limit_key)

        if current_count is None:
            return False

        return int(str(current_count)) >= self.max_resends

    def _increment_rate_limit(self, email: str):
        """Increment rate limit counter for OTP generation."""
        rate_limit_key = self._get_rate_limit_key(email)
        pipe = self.redis.pipeline()
        pipe.incr(rate_limit_key)
        pipe.expire(rate_limit_key, self.rate_limit_window)
        pipe.execute()

    def _get_remaining_attempts(self, email: str) -> int:
        """Get remaining verification attempts for user."""
        attempt_key = self._get_attempt_key(email)
        current_attempts = self.redis.get(attempt_key)
        if current_attempts is None:
            return self.max_attempts
        return max(0, self.max_attempts - int(str(current_attempts)))

    def _get_remaining_resends(self, email: str) -> int:
        """Get remaining resend attempts for user."""
        resend_key = self._get_resend_key(email)
        current_resends = self.redis.get(resend_key)
        if current_resends is None:
            return self.max_resends
        return max(0, self.max_resends - int(str(current_resends)))

    def get_user_status(self, email: str) -> Dict[str, Any]:
        """Get comprehensive user status including limits and lockouts."""
        return {
            "is_locked_out": self._is_locked_out(email),
            "remaining_attempts": self._get_remaining_attempts(email),
            "remaining_resends": self._get_remaining_resends(email),
            "rate_limited": self._check_rate_limit(email),
            "lockout_expires_at": self._get_lockout_expiry(email),
        }

    def _get_lockout_expiry(self, email: str) -> Optional[datetime]:
        """Get lockout expiry time for user."""
        lockout_key = self._get_lockout_key(email)
        ttl = self.redis.ttl(lockout_key)
        if ttl and int(str(ttl)) > 0:
            return datetime.now() + timedelta(seconds=int(str(ttl)))
        return None

    def store_otp(self, user: EmailProvider, is_resend: bool = False) -> Dict[str, Any]:
        """
        Store user data and OTP in Redis, return OTP and metadata.

        Args:
            user: Object with email field (UserCreate or RequestPasswordReset)
            is_resend: Whether this is a resend request

        Returns:
            Dict containing OTP and metadata

        Raises:
            RateLimitExceeded: If rate limit is exceeded
            OTPServiceError: If user is locked out
        """
        email = user.email
        user_lock = self._get_user_lock(email)

        with user_lock:
            # Check if user is locked out
            if self._is_locked_out(email):
                lockout_expiry = self._get_lockout_expiry(email)
                raise OTPServiceError(
                    f"Account is temporarily locked. Try again after {lockout_expiry}"
                )

            # Check rate limit
            if self._check_rate_limit(email):
                raise RateLimitExceeded(
                    f"Too many OTP requests. Maximum {self.max_resends} requests per hour."
                )

            # Generate and store OTP
            otp = self.generate_otp()

            # For UserCreate objects, store the full user data
            # For other objects (like password reset), store minimal data
            if hasattr(user, 'model_dump_json') and callable(getattr(user, 'model_dump_json')):
                user_data = str(user.model_dump_json())  # type: ignore
            else:
                # Create minimal user data for password reset scenarios
                user_data = json.dumps({"email": email})

            # Store OTP with email identifier
            otp_key = f"otp:{email}:{otp}"
            self.redis.setex(otp_key, self.otp_ttl, user_data)

            # Increment rate limit counter
            self._increment_rate_limit(email)

            # If this is a resend, increment resend counter
            if is_resend:
                resend_key = self._get_resend_key(email)
                pipe = self.redis.pipeline()
                pipe.incr(resend_key)
                pipe.expire(resend_key, self.rate_limit_window)
                pipe.execute()

            return {
                "otp": otp,
                "expires_at": datetime.now() + timedelta(seconds=self.otp_ttl),
                "remaining_attempts": self.max_attempts,
                "remaining_resends": self._get_remaining_resends(email),
            }

    def resend_otp(self, user: EmailProvider) -> Dict[str, Any]:
        """
        Resend OTP to user.

        Args:
            user: Object with email field (UserCreate or RequestPasswordReset)

        Returns:
            Dict containing new OTP and metadata

        Raises:
            RateLimitExceeded: If resend limit is exceeded
            OTPServiceError: If user is locked out
        """
        email = user.email

        # Check remaining resends
        remaining_resends = self._get_remaining_resends(email)
        if remaining_resends <= 0:
            raise RateLimitExceeded(
                f"Maximum resend attempts ({self.max_resends}) exceeded. "
                "Please wait before requesting a new OTP."
            )

        return self.store_otp(user, is_resend=True)

    def verify_otp(self, email: str, otp: str) -> Optional[UserData]:
        """
        Verify OTP and return user data if valid.

        Args:
            email: User email
            otp: OTP to verify

        Returns:
            UserCreate object if OTP is valid, None otherwise

        Raises:
            MaxRetriesExceeded: If max verification attempts exceeded
            OTPServiceError: If user is locked out
        """
        user_lock = self._get_user_lock(email)

        with user_lock:
            # Check if user is locked out
            if self._is_locked_out(email):
                lockout_expiry = self._get_lockout_expiry(email)
                raise OTPServiceError(
                    f"Account is temporarily locked. Try again after {lockout_expiry}"
                )

            # Check remaining attempts
            remaining_attempts = self._get_remaining_attempts(email)
            if remaining_attempts <= 0:
                raise MaxRetriesExceeded(
                    f"Maximum verification attempts ({self.max_attempts}) exceeded. "
                    "Account is temporarily locked."
                )

            # Verify OTP
            otp_key = f"otp:{email}:{otp}"
            user_data = self.redis.get(otp_key)

            if not user_data:
                # Increment attempt counter
                self._increment_attempts(email)

                # Check if this was the last attempt
                if remaining_attempts <= 1:
                    self._lockout_user(email)
                    raise MaxRetriesExceeded(
                        "Maximum verification attempts exceeded. "
                        f"Account locked for {self.lockout_duration // 60} minutes."
                    )

                return None

            try:
                # Parse JSON string back to dict
                user_dict = json.loads(str(user_data))

                # Successful verification - cleanup
                self._cleanup_user_data(email)
                self.redis.delete(otp_key)

                # Return UserData if we have full user info, otherwise return a minimal object
                if all(key in user_dict for key in ['first_name', 'last_name', 'password']):
                    return UserData(**user_dict)
                else:
                    # For password reset scenarios, we only have email
                    # Return a UserData with minimal info (will need to be handled differently)
                    return UserData(
                        email=user_dict['email'],
                        first_name='',  # Will be ignored for password reset
                        last_name='',   # Will be ignored for password reset
                        password=''     # Will be ignored for password reset
                    )
            except (json.JSONDecodeError, ValidationError):
                # Increment attempt counter for invalid data
                self._increment_attempts(email)
                return None

    def _increment_attempts(self, email: str):
        """Increment verification attempt counter."""
        attempt_key = self._get_attempt_key(email)
        pipe = self.redis.pipeline()
        pipe.incr(attempt_key)
        pipe.expire(attempt_key, self.otp_ttl)
        pipe.execute()

    def _lockout_user(self, email: str):
        """Lock out user for specified duration."""
        lockout_key = self._get_lockout_key(email)
        self.redis.setex(lockout_key, self.lockout_duration, "locked")

    def _cleanup_user_data(self, email: str):
        """Clean up user-related keys after successful verification."""
        keys_to_delete = [
            self._get_attempt_key(email),
            self._get_resend_key(email),
            self._get_rate_limit_key(email),
        ]

        # Delete OTP keys (pattern matching)
        otp_pattern = f"otp:{email}:*"
        otp_keys = self.redis.keys(otp_pattern)

        all_keys = keys_to_delete + otp_keys
        if all_keys:
            self.redis.delete(*all_keys)

    def store_user(self, user: User) -> bool:
        """Store user data in Redis."""
        user_key = f"user:{user.email}"
        user_data = user.model_dump_json()
        return self.redis.setex(user_key, self.user_ttl, user_data)

    def get_user(self, email: str) -> Optional[User]:
        """Retrieve user data from Redis."""
        user_key = f"user:{email}"
        user_data = self.redis.get(user_key)

        if not user_data:
            return None

        try:
            user_dict = json.loads(user_data)
            return User(**user_dict)
        except (json.JSONDecodeError, ValidationError):
            return None

    def clear_user_locks(self, email: str):
        """Clear all locks and attempts for a user (admin function)."""
        user_lock = self._get_user_lock(email)

        with user_lock:
            self._cleanup_user_data(email)
            lockout_key = self._get_lockout_key(email)
            self.redis.delete(lockout_key)

    def get_service_stats(self) -> Dict[str, int]:
        """Get service statistics (admin function)."""
        patterns = [
            "otp:*",
            "otp_attempts:*",
            "otp_resend:*",
            "otp_lockout:*",
            "otp_rate_limit:*",
            "user:*"
        ]

        stats = {}
        for pattern in patterns:
            key_type = pattern.split(':')[0]
            count = len(self.redis.keys(pattern))
            stats[key_type] = count

        return stats


@lru_cache
def get_otp_service():
    return OTPService(r_database)

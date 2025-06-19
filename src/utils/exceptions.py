class OTPServiceError(Exception):
    """Custom exception for OTP service errors."""
    pass

class RateLimitExceeded(OTPServiceError):
    """Raised when rate limit is exceeded."""
    pass

class MaxRetriesExceeded(OTPServiceError):
    """Raised when max retry attempts are exceeded."""
    pass

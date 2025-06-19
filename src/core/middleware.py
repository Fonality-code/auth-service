from typing import Callable, Awaitable
from fastapi import Request
from fastapi.responses import JSONResponse
from jose import JWTError, jwt
from datetime import datetime, timezone
import time
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from src.core.config import get_settings

settings = get_settings()

class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]):
        start_time = time.time()
        # Process the request and catch any authentication errors
        try:
            response = await call_next(request)

            # Add processing time header
            process_time = time.time() - start_time
            response.headers["X-Process-Time"] = str(process_time)

            return response

        except JWTError as e:
            # Handle JWT validation errors globally
            return JSONResponse(
                status_code=401,
                content={
                    "success": False,
                    "detail": "Authentication error. Please login again.",
                    "error": str(e)
                }
            )
        except Exception as e:
            # Log the error but don't expose details
            print(f"Error processing request: {str(e)}")
            return JSONResponse(
                status_code=500,
                content={
                    "success": False,
                    "detail": "An error occurred while processing your request."
                }

            )

class TokenValidationMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]):
        # Only check auth routes that need token validation
        path = request.url.path

        # Skip validation for these paths
        skip_paths = [
            "/api/v1/login",
            "/api/v1/register",
            "/api/v1/verify-user",
            "/api/v1/request-password-reset",
            "/api/v1/reset-password",
            "/api/v1/refresh"
        ]

        if any(path.endswith(skip_path) for skip_path in skip_paths):
            return await call_next(request)

        # Check access token for protected routes
        access_token = request.cookies.get("access_token")
        if access_token:
            try:
                # Verify token
                payload = jwt.decode(
                    access_token,
                    settings.SECRET_KEY,
                    algorithms=[settings.ALGORITHM]
                )

                # Check token expiration
                exp = payload.get("exp")
                if exp and datetime.fromtimestamp(exp, timezone.utc) > datetime.now(timezone.utc):
                    # Token is valid, proceed with the request
                    return await call_next(request)

            except JWTError:
                # Token is invalid, let the request continue
                # The route handler will handle the authentication error
                pass

        # For failed validation, still allow the request to proceed
        # The route handler's Depends will raise the appropriate HTTP exceptions
        return await call_next(request)

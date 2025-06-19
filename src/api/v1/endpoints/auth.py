from fastapi import APIRouter, Depends, HTTPException, Response, Cookie, Request
from sqlalchemy.orm import Session
from src.schemas.user import User as UserSchema, UserCreate, TokenData, UserLogin, OTPSent, VerifyUser, RequestPasswordReset, ForgotPassword, ResetPassword, RegistrationResponse, ChangePassword
from src.models.user import User
from src.services.auth import authenticate_user, create_user, get_user, update_password
from src.core.security import create_access_token, create_refresh_token, get_password_hash, verify_password
from src.core.database import get_db
from jose import jwt, JWTError
from src.core.config import get_settings
from src.services.otp import get_otp_service
from src.services.email_service import get_auth_email_service
from src.services.session import (
    create_session,
    get_session_by_refresh_token,
    invalidate_session,
    get_user_active_sessions,
    invalidate_user_sessions,
    update_session_refresh_token
)

from src.schemas.auth import (
    LoginSuccessResponse,
    CurrentUser,
    GetCurrentUserResponse,
    SessionResponse
)

from src.schemas.response import (
    APIResponse
)

from typing import Optional, List
from datetime import datetime

router = APIRouter()
settings = get_settings()
otp_service = get_otp_service()
email_service = get_auth_email_service()


@router.post("/register", response_model=RegistrationResponse)
def register_user(user: UserCreate, db: Session = Depends(get_db)) -> RegistrationResponse:
    res = otp_service.store_otp(user)

    otp = res['otp']
    expires_at = res["expires_at"].ctime()
    remaining_attempts = res["remaining_attempts"]
    remaining_resends = res["remaining_resends"]

    # Get user's full name for email
    user_name = f"{user.first_name} {user.last_name}"

    if settings.ENVIRONMENT == 'development':
        # In development, print to console and optionally send email
        print(f"Registration OTP for {user.email}: {otp}")
        print(f"Expires at: {expires_at}")
        print(f"Remaining attempts: {remaining_attempts}")
        print(f"Remaining resends: {remaining_resends}")

        # Try to send email in development (if email config is set up)
        try:
            email_service.send_account_verification_email(
                email=user.email,
                user_name=user_name,
                otp_code=otp,
                expiry_minutes=5
            )
        except Exception as e:
            print(f"Failed to send verification email: {e}")
    else:
        # In production, only send email
        try:
            email_sent = email_service.send_account_verification_email(
                email=user.email,
                user_name=user_name,
                otp_code=otp,
                expiry_minutes=5
            )
            if not email_sent:
                raise HTTPException(
                    status_code=500,
                    detail="Failed to send verification email. Please try again."
                )
        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail="Failed to send verification email. Please try again."
            )

    return RegistrationResponse(
        success=True,
        message=f"A verification code has been sent to {user.email}. Please check your email and enter the code to complete registration.",
    )



@router.post('/verify-user', response_model=UserSchema)
def verify_user(otpData: VerifyUser, db: Session = Depends(get_db)):
    data = otp_service.verify_otp(otpData.email, otpData.otp)

    if not data:
        raise HTTPException(status_code=401, detail="Invalid OTP")

    if data:
        user = create_user(db, data)

        if settings.ENVIRONMENT == 'development':
            # send account creation email
            print(f"User verified and created: {user.email}")
        return user
    else:
        raise HTTPException(status_code=401, detail="Invalid OTP")


@router.post("/login")
def login_user(request: Request, response: Response, user: UserLogin, db: Session = Depends(get_db)) -> LoginSuccessResponse:
    db_user = authenticate_user(db, user.email, user.password)
    if not db_user:
        raise HTTPException(status_code=401, detail="Incorrect email or password")

    access_token = create_access_token(data={"sub": db_user.email})
    refresh_token = create_refresh_token(data={"sub": db_user.email})

    # Set HTTP-only cookies with lax same-site policy for better compatibility
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        secure=True,
        samesite="lax"  # Changed from strict to lax
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
        secure=True,
        samesite="lax"  # Changed from strict to lax
    )

    # Create a session record
    user_agent = request.headers.get("user-agent", "")
    client_ip = request.client.host if request.client else None

    session = create_session(
        db=db,
        user_id=db_user.user_id,
        refresh_token=refresh_token,
        user_agent=user_agent,
        ip_address=client_ip
    )

    print(f"Created session {session.session_id} for user {db_user.email}")

    # Return user data
    return LoginSuccessResponse(
        success=True,
        message="Login successful",
        user=db_user,
        session_id=str(session.session_id),
    )

@router.post("/logout")
def logout_user(
    response: Response,
    db: Session = Depends(get_db),
    refresh_token: Optional[str] = Cookie(None)
) -> APIResponse:
    """Log out user by invalidating their session"""
    if refresh_token:
        session = get_session_by_refresh_token(db, refresh_token)
        if session:
            invalidate_session(db, session.session_id)
            print(f"Invalidated session {session.session_id}")

    # Clear cookies regardless
    response.delete_cookie(key="access_token")
    response.delete_cookie(key="refresh_token")

    return APIResponse(
        success=True,
        message="Logged out successfully"
    )

# Forgot password endpoint - user-friendly alternative to request-password-reset
@router.post("/forgot-password")
def forgot_password(forgot_request: ForgotPassword, db: Session = Depends(get_db)) -> APIResponse:
    """
    Forgot password endpoint - sends a password reset code to the user's email.

    This is a user-friendly endpoint that:
    - Generates a secure random verification code
    - Sends it to the user's email with a professional template
    - Provides clear instructions on next steps
    - Never reveals whether the email exists for security
    """
    # Check if user exists
    user = get_user(db, email=forgot_request.email)

    if user:
        try:
            # Generate and store OTP
            # Convert ForgotPassword to RequestPasswordReset for the OTP service
            reset_request = RequestPasswordReset(email=forgot_request.email)
            res = otp_service.store_otp(reset_request)

            otp = res['otp']
            expires_at = res["expires_at"].ctime()
            remaining_attempts = res["remaining_attempts"]
            remaining_resends = res["remaining_resends"]

            # Get user's full name for email
            user_name = f"{user.first_name} {user.last_name}"

            if settings.ENVIRONMENT == 'development':
                # In development, print to console and optionally send email
                print(f"🔐 Forgot Password Code for {forgot_request.email}: {otp}")
                print(f"Expires at: {expires_at}")
                print(f"Remaining attempts: {remaining_attempts}")
                print(f"Remaining resends: {remaining_resends}")

                # Try to send email in development
                try:
                    email_service.send_password_reset_email(
                        email=user.email,
                        user_name=user_name,
                        otp_code=otp,
                        expires_at=expires_at,
                        expiry_minutes=5,
                        remaining_attempts=remaining_attempts,
                        remaining_resends=remaining_resends
                    )
                    print(f"📧 Password reset email sent to {user.email}")
                except Exception as e:
                    print(f"❌ Failed to send password reset email: {e}")
            else:
                # In production, only send email
                try:
                    email_service.send_password_reset_email(
                        email=user.email,
                        user_name=user_name,
                        otp_code=otp,
                        expires_at=expires_at,
                        expiry_minutes=5,
                        remaining_attempts=remaining_attempts,
                        remaining_resends=remaining_resends
                    )
                except Exception as e:
                    # Log error but don't reveal to user
                    print(f"Failed to send password reset email: {e}")

        except Exception as e:
            # Log error but don't reveal to user for security
            print(f"Error in forgot password process: {e}")

    # Always return success message for security (don't reveal if email exists)
    return APIResponse(
        success=True,
        message="If an account with that email exists, we've sent a password reset code. Please check your email (including spam folder) and follow the instructions."
    )

# Password reset request
@router.post("/request-password-reset", response_model=OTPSent)
def request_password_reset(reset_request: RequestPasswordReset, db: Session = Depends(get_db)) -> APIResponse:
    # Check if user exists
    user = get_user(db, email=reset_request.email)
    if not user:
        # Don't reveal that the user doesn't exist for security reasons
        return APIResponse(
            success=True,
            message=f"If the email exists, a password reset code has been sent to {reset_request.email}"
        )

    # Generate and store OTP
    res = otp_service.store_otp(reset_request)

    otp = res['otp']
    expires_at = res["expires_at"].ctime()
    remaining_attempts = res["remaining_attempts"]
    remaining_resends = res["remaining_resends"]

    # Get user's full name for email
    user_name = f"{user.first_name} {user.last_name}"

    if settings.ENVIRONMENT == 'development':
        # In development, print to console and optionally send email
        print(f"Password reset OTP for {reset_request.email}: {otp}")
        print(f"Expires at: {expires_at}")
        print(f"Remaining attempts: {remaining_attempts}")
        print(f"Remaining resends: {remaining_resends}")

        # Try to send email in development (if email config is set up)
        try:
            email_service.send_password_reset_email(
                email=user.email,
                user_name=user_name,
                otp_code=otp,
                expires_at=expires_at,
                expiry_minutes=5,
                remaining_attempts=remaining_attempts,
                remaining_resends=remaining_resends
            )
        except Exception as e:
            print(f"Failed to send password reset email: {e}")
    else:
        # In production, only send email
        try:
            email_sent = email_service.send_password_reset_email(
                email=user.email,
                user_name=user_name,
                otp_code=otp,
                expires_at=expires_at,
                expiry_minutes=5,
                remaining_attempts=remaining_attempts,
                remaining_resends=remaining_resends
            )
            if not email_sent:
                # Don't reveal failure details for security
                return APIResponse(
                    success=True,
                    message=f"If the email exists, a password reset code has been sent to {reset_request.email}"
                )
        except Exception as e:
            # Don't reveal failure details for security
            return APIResponse(
                success=True,
                message=f"If the email exists, a password reset code has been sent to {reset_request.email}"
            )

    return APIResponse(
        success=True,
        message=f"A password reset code has been sent to {reset_request.email}. Please check your email."
    )

# Verify OTP and reset password
@router.post("/reset-password")
def reset_password(reset_data: ResetPassword, db: Session = Depends(get_db)) -> APIResponse:
    # Verify OTP
    user_data = otp_service.verify_otp(reset_data.email, reset_data.otp)

    if not user_data:
        raise HTTPException(status_code=401, detail="Invalid OTP")

    # Check if user exists
    user = get_user(db, email=reset_data.email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Update password
    hashed_password = get_password_hash(reset_data.new_password)
    update_password(db, user, hashed_password)

    print(f"Password reset successful for {user.email}")

    return APIResponse(
        success=True,
        message="Password has been reset successfully. You can now log in with your new password."
    )

# Check password reset status
@router.get("/forgot-password/status/{email}")
def get_password_reset_status(email: str, db: Session = Depends(get_db)) -> APIResponse:
    """
    Get the status of a password reset request for debugging/support purposes.
    Note: This endpoint should be used carefully in production.
    """
    if settings.ENVIRONMENT != 'development':
        raise HTTPException(status_code=404, detail="Endpoint not available")

    try:
        # Get user status from OTP service
        status = otp_service.get_user_status(email)

        return APIResponse(
            success=True,
            message="Password reset status retrieved",
            # Adding extra data for development debugging
        )
    except Exception as e:
        return APIResponse(
            success=False,
            message=f"Could not retrieve status: {str(e)}"
        )

@router.post("/resend-otp", response_model=OTPSent)
def resend_otp(resend_request: RequestPasswordReset, db: Session = Depends(get_db)) -> APIResponse:
    # Check if user exists for password reset, or if this is a registration resend
    user = get_user(db, email=resend_request.email)

    # Create a UserCreate-like object for the OTP service
    res = otp_service.resend_otp(resend_request)

    if not res:
        raise HTTPException(status_code=400, detail="Could not resend OTP. Maximum resend limit reached or no pending OTP found.")

    otp = res['otp']
    expires_at = res["expires_at"].ctime()
    remaining_attempts = res["remaining_attempts"]
    remaining_resends = res["remaining_resends"]

    # Determine the context (password reset vs registration)
    is_password_reset = user is not None
    user_name = f"{user.first_name} {user.last_name}" if user else "User"

    if settings.ENVIRONMENT == 'development':
        # In development, print to console and optionally send email
        print(f"Resent OTP for {resend_request.email}: {otp}")
        print(f"Expires at: {expires_at}")
        print(f"Remaining attempts: {remaining_attempts}")
        print(f"Remaining resends: {remaining_resends}")

        # Try to send email in development
        try:
            if is_password_reset:
                email_service.send_password_reset_email(
                    email=resend_request.email,
                    user_name=user_name,
                    otp_code=otp,
                    expires_at=expires_at,
                    expiry_minutes=5,
                    remaining_attempts=remaining_attempts,
                    remaining_resends=remaining_resends
                )
            else:
                # This is likely a registration resend
                email_service.send_account_verification_email(
                    email=resend_request.email,
                    user_name=user_name,
                    otp_code=otp,
                    expiry_minutes=5
                )
        except Exception as e:
            print(f"Failed to send resend email: {e}")
    else:
        # In production, send email
        try:
            if is_password_reset:
                email_service.send_password_reset_email(
                    email=resend_request.email,
                    user_name=user_name,
                    otp_code=otp,
                    expires_at=expires_at,
                    expiry_minutes=5,
                    remaining_attempts=remaining_attempts,
                    remaining_resends=remaining_resends
                )
            else:
                email_service.send_account_verification_email(
                    email=resend_request.email,
                    user_name=user_name,
                    otp_code=otp,
                    expiry_minutes=5
                )
        except Exception as e:
            # Don't reveal failure details
            pass

    return APIResponse(
        success=True,
        message=f"A new verification code has been sent to {resend_request.email}.",
    )

# Basic token validation without session checking (for internal use)
async def get_token_data_basic(access_token: Optional[str] = Cookie(None)) -> TokenData:
    if not access_token:
        raise HTTPException(
            status_code=401,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = jwt.decode(access_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        email: Optional[str] = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")

        # Verify token has not expired
        exp = payload.get("exp")
        if not exp or datetime.fromtimestamp(exp, tz=datetime.now().astimezone().tzinfo) < datetime.now().astimezone():
            raise HTTPException(status_code=401, detail="Token has expired")

        return TokenData(email=email)
    except JWTError as e:
        print(f"JWT validation error: {str(e)}")
        raise HTTPException(
            status_code=401,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

# Enhanced token validation that also checks for active sessions and returns user
async def get_current_user_from_token(
    access_token: Optional[str] = Cookie(None),
    db: Session = Depends(get_db)
) -> User:
    # First validate the JWT token
    token_data = await get_token_data_basic(access_token)

    # Get the user from the database
    if token_data.email is None:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = get_user(db, email=token_data.email)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    # Check if the user has any active sessions
    active_sessions = get_user_active_sessions(db, user.user_id)
    if not active_sessions:
        raise HTTPException(
            status_code=401,
            detail="No active sessions found. Please login again."
        )

    return user

# Enhanced token validation that also checks for active sessions
async def get_token_data(
    access_token: Optional[str] = Cookie(None),
    db: Session = Depends(get_db)
) -> TokenData:
    # First validate the JWT token
    token_data = await get_token_data_basic(access_token)

    # Get the user from the database
    if token_data.email is None:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = get_user(db, email=token_data.email)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    # Check if the user has any active sessions
    active_sessions = get_user_active_sessions(db, user.user_id)
    if not active_sessions:
        raise HTTPException(
            status_code=401,
            detail="No active sessions found. Please login again."
        )

    return token_data

# Improve the current user endpoint to include more details for client
@router.get("/me")
def get_current_user(db_user: User = Depends(get_current_user_from_token)) -> GetCurrentUserResponse:
    # get_current_user_from_token already validates both JWT and active sessions
    # and returns the user object directly
    current_user = CurrentUser(
        id=db_user.id,
        user_id=db_user.user_id,
        email=db_user.email,
        first_name=db_user.first_name,
        last_name=db_user.last_name,
        is_active=db_user.is_active,
        roles=db_user.get_active_roles(),
        permissions=db_user.get_all_permissions()
    )

    # Return data in a consistent format matching other endpoints
    return GetCurrentUserResponse(
        success=True,
        message="Current user retrieved successfully",
        user=current_user
    )

# Enhance the refresh token endpoint
@router.post("/refresh")
def refresh_token_endpoint(
    request: Request,
    response: Response,
    refresh_token: Optional[str] = Cookie(None),
    db: Session = Depends(get_db)
) -> GetCurrentUserResponse:
    # Better error handling for missing token
    if not refresh_token:
        response.delete_cookie(key="access_token")
        response.delete_cookie(key="refresh_token")
        raise HTTPException(
            status_code=401,
            detail="Refresh token is missing. Please login again."
        )

    try:
        # Validate the token
        payload = jwt.decode(refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")

        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token")

        # Check if session exists and is valid
        session = get_session_by_refresh_token(db, refresh_token)
        if not session:
            # Clean up cookies if session is invalid
            response.delete_cookie(key="access_token")
            response.delete_cookie(key="refresh_token")
            raise HTTPException(status_code=401, detail="Session expired or invalid. Please login again.")

        # Get the user
        db_user = get_user(db, email=email)
        if not db_user or db_user.user_id != session.user_id:
            response.delete_cookie(key="access_token")
            response.delete_cookie(key="refresh_token")
            raise HTTPException(status_code=401, detail="User not found or session mismatch")

        # Generate new tokens
        new_access_token = create_access_token(data={"sub": email})
        new_refresh_token = create_refresh_token(data={"sub": email})

        # Update session with new refresh token
        update_session_refresh_token(db, session, new_refresh_token)

        # Set new cookies
        response.set_cookie(
            key="access_token",
            value=new_access_token,
            httponly=True,
            max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            secure=True,
            samesite="lax"
        )
        response.set_cookie(
            key="refresh_token",
            value=new_refresh_token,
            httponly=True,
            max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
            secure=True,
            samesite="lax"
        )

        # Return user data with the refresh to avoid an extra API call
        current_user = CurrentUser(
            id=db_user.id,
            user_id=db_user.user_id,
            email=db_user.email,
            first_name=db_user.first_name,
            last_name=db_user.last_name,
            is_active=db_user.is_active,
            roles=db_user.get_active_roles(),
            permissions=db_user.get_all_permissions()
        )

        return GetCurrentUserResponse(
            success=True,
            message="Token refreshed successfully",
            user=current_user
        )

        return GetCurrentUserResponse(
            success=True,
            message="Token refreshed successfully",
            user=current_user
        )


    except JWTError as e:
        # Clean cookies on error
        response.delete_cookie(key="access_token")
        response.delete_cookie(key="refresh_token")
        print(f"JWT Error during refresh: {str(e)}")
        raise HTTPException(
            status_code=401,
            detail="Authentication expired. Please login again."
        )

# Add a session management endpoint
@router.get("/sessions", response_model=List[SessionResponse])
def get_sessions(
    current_user: User = Depends(get_current_user_from_token),
    db: Session = Depends(get_db)
) -> List[SessionResponse]:
    """Get all active sessions for the current user"""
    sessions = get_user_active_sessions(db, current_user.user_id)

    return [
        SessionResponse(
            session_id=session.session_id,
            user_agent=session.user_agent or "",  # Handle None values
            ip_address=session.ip_address or "",   # Handle None values
            created_at=session.created_at.isoformat(),
            updated_at=session.updated_at.isoformat(),
            expires_at=session.expires_at.isoformat() if session.expires_at else None
        )
        for session in sessions
    ]

@router.delete("/sessions/{session_id}")
def revoke_session(
    session_id: str,
    current_user: User = Depends(get_current_user_from_token),
    db: Session = Depends(get_db)
) -> APIResponse:
    """Revoke a specific session"""
    # Get all user sessions to verify ownership
    sessions = get_user_active_sessions(db, current_user.user_id)
    session_ids = [session.session_id for session in sessions]

    if session_id not in session_ids:
        raise HTTPException(status_code=404, detail="Session not found or does not belong to you")

    success = invalidate_session(db, session_id)

    if success:
        return APIResponse(
            success=True,
            message=f"Session {session_id} has been successfully revoked"
        )
    else:
        raise HTTPException(status_code=500, detail="Failed to revoke session")

@router.delete("/sessions")
def revoke_all_sessions(
    current_only: bool = False,
    current_user: User = Depends(get_current_user_from_token),
    db: Session = Depends(get_db),
    refresh_token: Optional[str] = Cookie(None)
) -> APIResponse:
    """Revoke all sessions for the current user"""
    # Optionally keep the current session
    current_session_id = None
    if current_only and refresh_token:
        session = get_session_by_refresh_token(db, refresh_token)
        if session:
            current_session_id = session.session_id

    count = invalidate_user_sessions(db, current_user.user_id, exclude_session_id=current_session_id)

    return APIResponse(
        success=True,
        message=f"All sessions have been revoked. {count} sessions were affected."
    )

# Password change endpoint
@router.post("/change-password")
def change_password(
    password_data: ChangePassword,
    current_user: User = Depends(get_current_user_from_token),
    db: Session = Depends(get_db)
) -> APIResponse:
    """
    Change user password with proper validation.

    Requires:
    - current_password: Current password for verification
    - new_password: New password (minimum 8 characters)
    - confirm_password: Must match new_password
    """
    # Verify current password
    if not verify_password(password_data.current_password, current_user.hashed_password):
        raise HTTPException(status_code=401, detail="Current password is incorrect")

    # Check if new password is different from current password
    if verify_password(password_data.new_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="New password must be different from current password")

    # Update password
    hashed_password = get_password_hash(password_data.new_password)
    update_password(db, current_user, hashed_password)

    print(f"Password changed successfully for {current_user.email}")

    return APIResponse(
        success=True,
        message="Password has been changed successfully."
    )

from typing import Optional
from src.core.mail import GmailEmailService, EmailConfig, EmailMessage
from src.core.config import get_settings
import logging

logger = logging.getLogger(__name__)
settings = get_settings()

class AuthEmailService:
    """Email service for authentication-related emails"""

    def __init__(self):
        self.config = EmailConfig()

        # Check if email is configured
        self.email_configured = bool(
            self.config.username and
            self.config.password and
            self.config.sender_email
        )

        if self.email_configured:
            self.email_service = GmailEmailService(
                config=self.config,
                template_dir="src/templates/email"
            )
            self._create_templates()
        else:
            logger.warning("Email service not configured. Email credentials missing.")
            self.email_service = None

    def _create_templates(self):
        """Create email templates for authentication"""

        if not self.email_service:
            logger.warning("Email service not available. Cannot create templates.")
            return

        # Password reset template
        password_reset_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Password Reset Request</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                }
                .header {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 30px 20px;
                    text-align: center;
                    border-radius: 10px 10px 0 0;
                }
                .content {
                    background: #f9f9f9;
                    padding: 30px;
                    border-radius: 0 0 10px 10px;
                }
                .otp-code {
                    background: #e7f3ff;
                    border: 2px solid #2196F3;
                    border-radius: 8px;
                    padding: 20px;
                    text-align: center;
                    margin: 20px 0;
                }
                .otp-number {
                    font-size: 32px;
                    font-weight: bold;
                    color: #2196F3;
                    letter-spacing: 8px;
                    font-family: 'Courier New', monospace;
                }
                .alert {
                    background-color: #fff3cd;
                    border: 1px solid #ffeaa7;
                    padding: 15px;
                    border-radius: 5px;
                    margin: 20px 0;
                }
                .footer {
                    text-align: center;
                    margin-top: 30px;
                    padding-top: 20px;
                    border-top: 1px solid #ddd;
                    font-size: 12px;
                    color: #666;
                }
                .btn {
                    display: inline-block;
                    background-color: #2196F3;
                    color: white;
                    padding: 12px 24px;
                    text-decoration: none;
                    border-radius: 5px;
                    font-weight: bold;
                    margin: 10px 0;
                }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🔐 Password Reset Request</h1>
                <p>We received a request to reset your password</p>
            </div>

            <div class="content">
                <p>Hello <strong>{{ user_name }}</strong>,</p>

                <p>You recently requested to reset your password for your account. Use the verification code below to proceed:</p>

                <div class="otp-code">
                    <p><strong>Your verification code is:</strong></p>
                    <div class="otp-number">{{ otp_code }}</div>
                    <p><small>This code will expire in {{ expiry_minutes }} minutes</small></p>
                </div>

                <div class="alert">
                    <strong>⚠️ Security Notice:</strong> If you didn't request this password reset, please ignore this email. Your password will remain unchanged.
                </div>

                <p><strong>What's next?</strong></p>
                <ol>
                    <li>Go back to the password reset page</li>
                    <li>Enter the verification code: <strong>{{ otp_code }}</strong></li>
                    <li>Create your new password</li>
                </ol>

                <p><strong>Additional Information:</strong></p>
                <ul>
                    <li>Code expires: {{ expires_at }}</li>
                    <li>Remaining attempts: {{ remaining_attempts }}</li>
                    <li>Remaining resend attempts: {{ remaining_resends }}</li>
                </ul>

                <p>If you're having trouble, you can request a new code or contact our support team.</p>

                <p>Best regards,<br>
                <strong>{{ company_name }} Security Team</strong></p>
            </div>

            <div class="footer">
                <p>&copy; 2025 {{ company_name }}. All rights reserved.</p>
                <p>This is an automated message, please do not reply to this email.</p>
            </div>
        </body>
        </html>
        """

        # Account verification template
        account_verification_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Account Verification</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                }
                .header {
                    background: linear-gradient(135deg, #4CAF50 0%, #45a049 100%);
                    color: white;
                    padding: 30px 20px;
                    text-align: center;
                    border-radius: 10px 10px 0 0;
                }
                .content {
                    background: #f9f9f9;
                    padding: 30px;
                    border-radius: 0 0 10px 10px;
                }
                .otp-code {
                    background: #e8f5e8;
                    border: 2px solid #4CAF50;
                    border-radius: 8px;
                    padding: 20px;
                    text-align: center;
                    margin: 20px 0;
                }
                .otp-number {
                    font-size: 32px;
                    font-weight: bold;
                    color: #4CAF50;
                    letter-spacing: 8px;
                    font-family: 'Courier New', monospace;
                }
                .footer {
                    text-align: center;
                    margin-top: 30px;
                    padding-top: 20px;
                    border-top: 1px solid #ddd;
                    font-size: 12px;
                    color: #666;
                }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🎉 Welcome to {{ company_name }}!</h1>
                <p>Please verify your account to get started</p>
            </div>

            <div class="content">
                <p>Hello <strong>{{ user_name }}</strong>,</p>

                <p>Thank you for creating an account with {{ company_name }}! To complete your registration, please verify your email address with the code below:</p>

                <div class="otp-code">
                    <p><strong>Your verification code is:</strong></p>
                    <div class="otp-number">{{ otp_code }}</div>
                    <p><small>This code will expire in {{ expiry_minutes }} minutes</small></p>
                </div>

                <p><strong>What's next?</strong></p>
                <ol>
                    <li>Go back to the verification page</li>
                    <li>Enter the verification code: <strong>{{ otp_code }}</strong></li>
                    <li>Start using your account!</li>
                </ol>

                <p>If you didn't create this account, please ignore this email.</p>

                <p>Welcome aboard!<br>
                <strong>The {{ company_name }} Team</strong></p>
            </div>

            <div class="footer">
                <p>&copy; 2025 {{ company_name }}. All rights reserved.</p>
            </div>
        </body>
        </html>
        """

        # Create templates
        try:
            self.email_service.create_template("password_reset", password_reset_template, "html")
            self.email_service.create_template("account_verification", account_verification_template, "html")
            logger.info("Email templates created successfully")
        except Exception as e:
            logger.error(f"Failed to create email templates: {e}")

    def send_password_reset_email(
        self,
        email: str,
        user_name: str,
        otp_code: str,
        expires_at: str,
        expiry_minutes: int = 5,
        remaining_attempts: int = 3,
        remaining_resends: int = 5,
        company_name: str = "Wayfinder"
    ) -> bool:
        """Send password reset email with OTP code"""

        if not self.email_configured or not self.email_service:
            logger.warning(f"Email service not configured. Cannot send password reset email to {email}")
            return False

        try:
            email_message = EmailMessage(
                to=[email],
                subject=f"🔐 Password Reset Code for {company_name}",
                template_name="password_reset",
                template_data={
                    "user_name": user_name,
                    "otp_code": otp_code,
                    "expires_at": expires_at,
                    "expiry_minutes": expiry_minutes,
                    "remaining_attempts": remaining_attempts,
                    "remaining_resends": remaining_resends,
                    "company_name": company_name
                }
            )

            success = self.email_service.send_email(email_message)

            if success:
                logger.info(f"Password reset email sent successfully to {email}")
            else:
                logger.error(f"Failed to send password reset email to {email}")

            return success

        except Exception as e:
            logger.error(f"Error sending password reset email to {email}: {e}")
            return False

    def send_account_verification_email(
        self,
        email: str,
        user_name: str,
        otp_code: str,
        expiry_minutes: int = 5,
        company_name: str = "Wayfinder"
    ) -> bool:
        """Send account verification email with OTP code"""

        if not self.email_configured or not self.email_service:
            logger.warning(f"Email service not configured. Cannot send verification email to {email}")
            return False

        try:
            email_message = EmailMessage(
                to=[email],
                subject=f"🎉 Welcome to {company_name} - Verify Your Account",
                template_name="account_verification",
                template_data={
                    "user_name": user_name,
                    "otp_code": otp_code,
                    "expiry_minutes": expiry_minutes,
                    "company_name": company_name
                }
            )

            success = self.email_service.send_email(email_message)

            if success:
                logger.info(f"Account verification email sent successfully to {email}")
            else:
                logger.error(f"Failed to send account verification email to {email}")

            return success

        except Exception as e:
            logger.error(f"Error sending account verification email to {email}: {e}")
            return False

# Singleton instance
_email_service_instance: Optional[AuthEmailService] = None

def get_auth_email_service() -> AuthEmailService:
    """Get singleton instance of AuthEmailService"""
    global _email_service_instance
    if _email_service_instance is None:
        _email_service_instance = AuthEmailService()
    return _email_service_instance

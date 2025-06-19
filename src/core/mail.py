import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import os
from pathlib import Path
from typing import List, Optional, Dict, Any, TypedDict
import logging
from jinja2 import Environment, FileSystemLoader, Template
from dataclasses import dataclass

from src.core.config import get_settings

settings = get_settings()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class EmailConfig:
    """Email configuration settings"""
    smtp_server: str = "smtp.gmail.com"
    smtp_port: int = 587
    username: str =  settings.GMAIL_ACCOUNT
    password: str =  settings.GMAIL_APP_PASSWORD
    sender_name: str =  settings.GMAIL_SENDER_NAME
    sender_email: str =  settings.GMAIL_ACCOUNT

@dataclass
class EmailMessage:
    """Email message structure"""
    to: List[str]
    subject: str
    template_name: str
    template_data: Dict[str, Any]
    cc: Optional[List[str]] = None
    bcc: Optional[List[str]] = None
    attachments: Optional[List[str]] = None
    reply_to: Optional[str] = None


class EmailResult(TypedDict):
    total: int
    sent: int
    failed: int
    errors: List[Dict[str, Any]]


default_config = EmailConfig()

class GmailEmailService:
    """
    Gmail email service with Jinja2 template support

    Features:
    - Send emails via Gmail SMTP
    - HTML and text templates using Jinja2
    - Attachment support
    - CC/BCC support
    - Template inheritance and includes
    - Error handling and logging
    """

    def __init__(self, config: EmailConfig=default_config, template_dir: str = "templates"):
        self.config = config
        self.template_dir = Path(template_dir)
        self.template_dir.mkdir(exist_ok=True)

        # Setup Jinja2 environment
        self.jinja_env = Environment(
            loader=FileSystemLoader(self.template_dir),
            autoescape=True,
            trim_blocks=True,
            lstrip_blocks=True
        )

        # Validate configuration
        self._validate_config()

    def _validate_config(self):
        """Validate email configuration"""
        if not self.config.username or not self.config.password:
            raise ValueError("Username and password are required")

        if not self.config.sender_email:
            self.config.sender_email = self.config.username

    def create_template(self, name: str, content: str, template_type: str = "html"):
        """
        Create a new email template

        Args:
            name: Template name (without extension)
            content: Template content with Jinja2 syntax
            template_type: 'html' or 'text'
        """
        extension = "html" if template_type == "html" else "txt"
        template_path = self.template_dir / f"{name}.{extension}"

        with open(template_path, 'w', encoding='utf-8') as f:
            f.write(content)

        logger.info(f"Created template: {template_path}")

    def get_template(self, name: str) -> Template:
        """Load a Jinja2 template"""
        try:
            # Try HTML first, then text
            for ext in ['html', 'txt']:
                template_name = f"{name}.{ext}"
                if (self.template_dir / template_name).exists():
                    return self.jinja_env.get_template(template_name)

            raise FileNotFoundError(f"Template '{name}' not found")

        except Exception as e:
            logger.error(f"Error loading template '{name}': {e}")
            raise

    def render_template(self, template_name: str, data: Dict[str, Any]) -> str:
        """Render a template with data"""
        template = self.get_template(template_name)
        return template.render(**data)

    def _create_message(self, email_msg: EmailMessage) -> MIMEMultipart:
        """Create email message with rendered template"""
        msg = MIMEMultipart('alternative')

        # Set headers
        msg['From'] = f"{self.config.sender_name} <{self.config.sender_email}>"
        msg['To'] = ", ".join(email_msg.to)
        msg['Subject'] = email_msg.subject

        if email_msg.cc:
            msg['Cc'] = ", ".join(email_msg.cc)

        if email_msg.reply_to:
            msg['Reply-To'] = email_msg.reply_to

        # Render template content
        try:
            rendered_content = self.render_template(
                email_msg.template_name,
                email_msg.template_data
            )

            # Determine content type based on template extension
            template_path = None
            for ext in ['html', 'txt']:
                test_path = self.template_dir / f"{email_msg.template_name}.{ext}"
                if test_path.exists():
                    template_path = test_path
                    break

            if template_path and template_path.suffix == '.html':
                part = MIMEText(rendered_content, 'html', 'utf-8')
            else:
                part = MIMEText(rendered_content, 'plain', 'utf-8')

            msg.attach(part)

        except Exception as e:
            logger.error(f"Error rendering template: {e}")
            raise

        # Add attachments
        if email_msg.attachments:
            self._add_attachments(msg, email_msg.attachments)

        return msg

    def _add_attachments(self, msg: MIMEMultipart, attachments: List[str]):
        """Add file attachments to email"""
        for file_path in attachments:
            if not os.path.isfile(file_path):
                logger.warning(f"Attachment not found: {file_path}")
                continue

            try:
                with open(file_path, "rb") as attachment:
                    part = MIMEBase('application', 'octet-stream')
                    part.set_payload(attachment.read())

                encoders.encode_base64(part)
                filename = os.path.basename(file_path)
                part.add_header(
                    'Content-Disposition',
                    f'attachment; filename= {filename}'
                )
                msg.attach(part)

            except Exception as e:
                logger.error(f"Error adding attachment {file_path}: {e}")

    def send_email(self, email_msg: EmailMessage) -> bool:
        """
        Send email using Gmail SMTP

        Args:
            email_msg: EmailMessage object with email details

        Returns:
            bool: True if sent successfully, False otherwise
        """
        try:
            # Create message
            message = self._create_message(email_msg)

            # Get all recipients
            recipients = email_msg.to.copy()
            if email_msg.cc:
                recipients.extend(email_msg.cc)
            if email_msg.bcc:
                recipients.extend(email_msg.bcc)

            # Connect to Gmail SMTP
            context = ssl.create_default_context()

            with smtplib.SMTP(self.config.smtp_server, self.config.smtp_port) as server:
                server.starttls(context=context)
                server.login(self.config.username, self.config.password)

                # Send email
                text = message.as_string()
                server.sendmail(self.config.sender_email, recipients, text)

            return False

        except Exception as e:
            logger.error(f"Failed to send email to {email_msg.to}: {e}")
            return False

    class EmailResult(TypedDict):
        total: int
        sent: int
        failed: int
    def send_bulk_emails(self, emails: List[EmailMessage],
                        max_retries: int = 3) -> EmailResult:
        """
        Send multiple emails with retry logic

        Args:
            emails: List of EmailMessage objects
            max_retries: Maximum retry attempts per email

        Returns:
            Dict with success/failure statistics
        """
        results: EmailResult = {
            'total': len(emails),
            'sent': 0,
            'failed': 0,
            'errors': []
        }

        for i, email_msg in enumerate(emails):
            retry_count = 0
            sent = False

            while retry_count < max_retries and not sent:
                try:
                    sent = self.send_email(email_msg)
                    if sent:
                        results['sent'] += 1
                    else:
                        retry_count += 1

                except Exception as e:
                    retry_count += 1
                    if retry_count >= max_retries:
                        results['failed'] += 1
                        results['errors'].append({
                            'email_index': i,
                            'recipients': email_msg.to,
                            'error': str(e)
                        })

        return results



# Example usage and template creation
def create_sample_templates(service: GmailEmailService):
    """Create sample email templates"""

    # Welcome email template
    welcome_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Welcome to {{ company_name }}</title>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .header { background-color: #4CAF50; color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; }
            .footer { background-color: #f4f4f4; padding: 10px; text-align: center; font-size: 12px; }
            .btn { background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Welcome to {{ company_name }}!</h1>
        </div>
        <div class="content">
            <h2>Hello {{ user_name }}!</h2>
            <p>Thank you for joining {{ company_name }}. We're excited to have you on board!</p>

            {% if activation_link %}
            <p>To get started, please activate your account:</p>
            <p><a href="{{ activation_link }}" class="btn">Activate Account</a></p>
            {% endif %}

            <p>If you have any questions, feel free to contact our support team.</p>

            <p>Best regards,<br>
            The {{ company_name }} Team</p>
        </div>
        <div class="footer">
            <p>&copy; 2024 {{ company_name }}. All rights reserved.</p>
        </div>
    </body>
    </html>
    """

    # Password reset template
    reset_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Password Reset Request</title>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .alert { background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
            .btn { background-color: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>Password Reset Request</h2>

            <div class="alert">
                <strong>Security Notice:</strong> We received a request to reset your password.
            </div>

            <p>Hello {{ user_name }},</p>

            <p>You recently requested to reset your password. Click the button below to reset it:</p>

            <p><a href="{{ reset_link }}" class="btn">Reset Password</a></p>

            <p><strong>This link will expire in {{ expiry_hours }} hours.</strong></p>

            <p>If you didn't request this reset, please ignore this email or contact support if you have concerns.</p>

            <p>For security reasons, this link can only be used once.</p>

            <p>Best regards,<br>
            Security Team</p>
        </div>
    </body>
    </html>
    """

    # Newsletter template
    newsletter_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>{{ newsletter_title }}</title>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
            .container { max-width: 600px; margin: 0 auto; }
            .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px 20px; text-align: center; }
            .content { padding: 20px; }
            .article { margin-bottom: 30px; border-bottom: 1px solid #eee; padding-bottom: 20px; }
            .article h3 { color: #333; margin-top: 0; }
            .footer { background-color: #f8f9fa; padding: 20px; text-align: center; font-size: 12px; color: #666; }
            .social-links a { margin: 0 10px; text-decoration: none; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>{{ newsletter_title }}</h1>
                <p>{{ date }}</p>
            </div>

            <div class="content">
                <p>Hello {{ subscriber_name }},</p>

                {% for article in articles %}
                <div class="article">
                    <h3>{{ article.title }}</h3>
                    <p>{{ article.summary }}</p>
                    {% if article.link %}
                    <p><a href="{{ article.link }}">Read more...</a></p>
                    {% endif %}
                </div>
                {% endfor %}

                <p>Thank you for reading!</p>
            </div>

            <div class="footer">
                <div class="social-links">
                    <a href="{{ social.twitter }}">Twitter</a>
                    <a href="{{ social.linkedin }}">LinkedIn</a>
                    <a href="{{ social.website }}">Website</a>
                </div>
                <p>You're receiving this because you subscribed to our newsletter.</p>
                <p><a href="{{ unsubscribe_link }}">Unsubscribe</a></p>
            </div>
        </div>
    </body>
    </html>
    """

    # Create templates
    service.create_template("welcome", welcome_template, "html")
    service.create_template("password_reset", reset_template, "html")
    service.create_template("newsletter", newsletter_template, "html")

# Configuration and usage example
def main():
    """Example usage of the Gmail Email Service"""

    # Load configuration (you can also use environment variables or config files)
    config = EmailConfig( )

    # Initialize service
    service = GmailEmailService(config, template_dir="email_templates")

    # Create sample templates
    create_sample_templates(service)

    # Example: Send welcome email
    welcome_email = EmailMessage(
        to=["ivan8tana@gmail.com"],
        subject="Welcome to Our Platform!",
        template_name="welcome",
        template_data={
            "user_name": "Ivan Tana",
            "company_name": "Fonality Code",
            "activation_link": "https://yoursite.com/activate?token=abc123"
        }
    )

    # # Example: Send password reset email
    # reset_email = EmailMessage(
    #     to=["user@example.com"],
    #     subject="Password Reset Request",
    #     template_name="password_reset",
    #     template_data={
    #         "user_name": "John Doe",
    #         "reset_link": "https://yoursite.com/reset?token=xyz789",
    #         "expiry_hours": 24
    #     }
    # )

    # Example: Send newsletter
    newsletter_email = EmailMessage(
        to=["ivan8tana@gmail.com"],
        subject="Weekly Tech Newsletter",
        template_name="newsletter",
        template_data={
            "newsletter_title": "Weekly Tech Update",
            "date": "March 15, 2024",
            "subscriber_name": "Jane Smith",
            "articles": [
                {
                    "title": "Latest in AI Technology",
                    "summary": "Discover the newest developments in artificial intelligence...",
                    "link": "https://yoursite.com/ai-news"
                },
                {
                    "title": "Web Development Trends",
                    "summary": "Stay updated with the latest web development practices...",
                    "link": "https://yoursite.com/web-trends"
                }
            ],
            "social": {
                "twitter": "https://twitter.com/yourcompany",
                "linkedin": "https://linkedin.com/company/yourcompany",
                "website": "https://yoursite.com"
            },
            "unsubscribe_link": "https://yoursite.com/unsubscribe?token=unsubtoken"
        }
    )

    # Send individual emails
    service.send_email(welcome_email)
    # service.send_email(reset_email)
    # service.send_email(newsletter_email)

    # Send bulk emails
    # emails = [welcome_email, newsletter_email]
    # results = service.send_bulk_emails(emails)
    # print(f"Bulk email results: {results}")

if __name__ == "__main__":
    main()

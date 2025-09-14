import boto3
import os
import logging
import random
from django.conf import settings
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import smart_bytes
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils import timezone
from datetime import timedelta
from rest_framework.exceptions import ValidationError
from ..models.payment import Plan
from ..models.dashboard_user import DashboardUserOTP, UserSubscription

logger = logging.getLogger(__name__)


def send_email_via_ses(client, sender, recipient, subject, html_body, charset):
    """
    Sends an email using AWS SES with HTML content.

    Args:
        client: boto3 SES client instance.
        sender (str): Verified sender email address.
        recipient (str): Recipient email address.
        subject (str): Subject of the email.
        html_body (str): HTML content of the email.
        charset (str): Character set for the email content.
    """
    client.send_email(
        Destination={"ToAddresses": [recipient]},
        Message={
            "Body": {"Html": {"Charset": charset, "Data": html_body}},
            "Subject": {"Charset": charset, "Data": subject},
        },
        Source=sender,
    )


def send_password_reset_email(user):
    """
    Sends a password reset email to the user via AWS SES.

    Args:
        user (User): The user requesting a password reset.

    Returns:
        dict: A dictionary indicating success or failure.
    """
    charset = "UTF-8"
    client = boto3.client("ses", region_name="us-east-2")
    sender = os.getenv("EMAIL_SENDER")
    recipient = user.email
    subject = "Password Reset Request"

    uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
    token = PasswordResetTokenGenerator().make_token(user)
    current_site = settings.FRONTEND_URL
    reset_link = (
        f"{current_site}/account/password-reset-confirm/?uidb64={uidb64}&token={token}"
    )

    # HTML email template
    html_body = f"""
    <html>
        <body>
            <h3>Hello {user.name_english},</h3>
            <p>Click the link below to reset your password:</p>
            <a href="{reset_link}" target="_blank">{reset_link}</a>
            <p>If you did not request this, please ignore this email.</p>
        </body>
    </html>
    """

    return send_email_via_ses(client, sender, recipient, subject, html_body, charset)


def generate_otp_code():
    return str(random.randint(100000, 999999))


def send_otp_to_dashboard_user(user):
    otp_code = generate_otp_code()
    expiry_time = timezone.now() + timedelta(minutes=30)

    otp_obj, _ = DashboardUserOTP.objects.update_or_create(
        user=user,
        defaults={"otp_code": otp_code, "expires_at": expiry_time}
    )

charset = "UTF-8"
client = boto3.client("ses", region_name="us-east-2")
sender = os.getenv("EMAIL_SENDER")
    recipient = user.email
    subject = "Zory OTP Code"


    # HTML email template
    html_body = f"""
        <html>
            <body>
                <h3>Hello {user.name_english},</h3>
                <p>Your OTP is: <strong>{otp_code}</strong>.</p>
                <p>It expires in 30 minutes</p>
                <p>If you did not request this, Please ignore this email.</p>
            </body>
        </html>
        """

    return send_email_via_ses(client, sender, recipient, subject, html_body, charset)


def normalize_email(email):
    """
    Normalize email by:
    - Lowercasing.
    - Removing '+' tags (Gmail-style).
    - Optionally remove dots (for Gmail only).
    """
    email = email.strip().lower()
    local_part, domain = email.split('@', 1)

    local_part = local_part.split('+')[0]

    return f"{local_part}@{domain}"


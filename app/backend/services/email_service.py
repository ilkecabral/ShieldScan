"""
email_service.py — Transactional email sender
Uses Gmail SMTP with an App Password (free, no extra dependencies).

Setup (one-time):
  1. Enable 2-Step Verification on your Google account
  2. Go to: https://myaccount.google.com/apppasswords
  3. Create an App Password → copy the 16-char code
  4. In .env set:
       EMAIL_USER=your@gmail.com
       EMAIL_PASSWORD=xxxx xxxx xxxx xxxx   ← the 16-char App Password (spaces OK)

Sends:
  - Email verification code (on signup)
  - Password reset link (on forgot-password request)
"""

import os
import smtplib
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

# ── Config from .env ──────────────────────────────────────────
EMAIL_HOST     = os.getenv("EMAIL_HOST", "smtp.gmail.com")
EMAIL_PORT     = int(os.getenv("EMAIL_PORT", "587"))
EMAIL_USER     = os.getenv("EMAIL_USER", "")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "")
EMAIL_FROM     = os.getenv("EMAIL_FROM", f"ShieldScan <{EMAIL_USER}>")
APP_URL        = os.getenv("APP_URL", "http://localhost:3000")


# ── Internal helpers ──────────────────────────────────────────

def _is_configured() -> bool:
    """Return True if SMTP credentials are set."""
    return bool(EMAIL_USER and EMAIL_PASSWORD)


def _send(to: str, subject: str, html: str, text: str) -> None:
    """
    Send a single email via Gmail SMTP (TLS on port 587).
    Raises RuntimeError if email is not configured.
    Raises smtplib.SMTPException on send failure.
    """
    if not _is_configured():
        raise RuntimeError(
            "Email not configured. Set EMAIL_USER and EMAIL_PASSWORD in .env.\n"
            "See app/backend/services/email_service.py for Gmail App Password setup."
        )

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = EMAIL_FROM
    msg["To"]      = to

    msg.attach(MIMEText(text, "plain"))
    msg.attach(MIMEText(html, "html"))

    with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
        server.ehlo()
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASSWORD.replace(" ", ""))  # strip spaces from App Password
        server.sendmail(EMAIL_USER, to, msg.as_string())

    logger.info("Email sent to %s — %s", to, subject)


def _base_html(content: str) -> str:
    """Wrap content in a consistent ShieldScan HTML email shell."""
    return f"""
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin:0;padding:0;background:#0f1117;font-family:'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0f1117;padding:40px 0;">
    <tr>
      <td align="center">
        <table width="560" cellpadding="0" cellspacing="0"
               style="background:#1a1d27;border-radius:12px;overflow:hidden;border:1px solid #2a2d3e;">

          <!-- Header -->
          <tr>
            <td style="background:linear-gradient(135deg,#6c63ff,#4facfe);padding:32px 40px;text-align:center;">
              <span style="font-size:28px;font-weight:700;color:#fff;letter-spacing:-0.5px;">
                🛡 ShieldScan
              </span>
              <p style="margin:6px 0 0;color:rgba(255,255,255,0.85);font-size:13px;">
                Cloud Security Platform
              </p>
            </td>
          </tr>

          <!-- Body -->
          <tr>
            <td style="padding:36px 40px;color:#c8cad8;">
              {content}
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="padding:20px 40px;border-top:1px solid #2a2d3e;text-align:center;
                       color:#555775;font-size:12px;">
              You received this email because an action was taken on your ShieldScan account.<br>
              If you didn't request this, you can safely ignore it.
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>
"""


# ── Public API ────────────────────────────────────────────────

def send_verification_email(to_email: str, full_name: str, code: str) -> None:
    """
    Send a 6-digit email verification code after signup.
    Code expires in 15 minutes (enforced by the backend).
    """
    name = full_name or "there"
    subject = "Verify your ShieldScan account"

    content = f"""
      <h2 style="margin:0 0 16px;color:#fff;font-size:22px;font-weight:600;">
        Verify your email address
      </h2>
      <p style="margin:0 0 24px;font-size:15px;line-height:1.6;color:#9496b0;">
        Hi {name}, welcome to ShieldScan! Enter the code below to activate your account.
      </p>

      <!-- Big code box -->
      <div style="background:#12141f;border:2px solid #6c63ff;border-radius:10px;
                  padding:28px;text-align:center;margin:0 0 28px;">
        <p style="margin:0 0 8px;font-size:12px;text-transform:uppercase;
                  letter-spacing:2px;color:#6c63ff;font-weight:600;">
          Verification Code
        </p>
        <p style="margin:0;font-size:42px;font-weight:700;color:#fff;
                  letter-spacing:12px;font-family:'Courier New',monospace;">
          {code}
        </p>
        <p style="margin:12px 0 0;font-size:12px;color:#555775;">
          Expires in 15 minutes
        </p>
      </div>

      <p style="margin:0;font-size:13px;color:#555775;line-height:1.6;">
        If you didn't create a ShieldScan account, no action is needed.
      </p>
    """

    text = f"""
ShieldScan — Email Verification

Hi {name},

Your verification code is: {code}

This code expires in 15 minutes.

If you didn't create a ShieldScan account, ignore this email.
"""

    _send(to_email, subject, _base_html(content), text)


def send_password_reset_email(to_email: str, full_name: str, reset_token: str) -> None:
    """
    Send a password reset link.
    The link encodes the token in the URL fragment so the frontend can auto-fill the form.
    Link expires in 60 minutes.
    """
    name = full_name or "there"
    reset_url = f"{APP_URL}/#reset?token={reset_token}"
    subject = "Reset your ShieldScan password"

    content = f"""
      <h2 style="margin:0 0 16px;color:#fff;font-size:22px;font-weight:600;">
        Reset your password
      </h2>
      <p style="margin:0 0 24px;font-size:15px;line-height:1.6;color:#9496b0;">
        Hi {name}, we received a request to reset your ShieldScan password.
        Click the button below — the link expires in <strong style="color:#fff;">60 minutes</strong>.
      </p>

      <!-- CTA button -->
      <div style="text-align:center;margin:0 0 28px;">
        <a href="{reset_url}"
           style="display:inline-block;padding:14px 36px;
                  background:linear-gradient(135deg,#6c63ff,#4facfe);
                  color:#fff;text-decoration:none;border-radius:8px;
                  font-size:15px;font-weight:600;letter-spacing:0.3px;">
          Reset Password
        </a>
      </div>

      <p style="margin:0 0 12px;font-size:13px;color:#555775;">
        Or copy and paste this link into your browser:
      </p>
      <p style="margin:0;font-size:12px;color:#6c63ff;word-break:break-all;
                background:#12141f;padding:12px;border-radius:6px;font-family:'Courier New',monospace;">
        {reset_url}
      </p>
    """

    text = f"""
ShieldScan — Password Reset

Hi {name},

Click the link below to reset your password (valid for 60 minutes):

{reset_url}

If you didn't request a password reset, ignore this email. Your password won't change.
"""

    _send(to_email, subject, _base_html(content), text)


def send_account_recovery_email(to_email: str, full_name: str, recovery_token: str) -> None:
    """
    Send an account recovery link to a soft-deleted user.
    The link encodes the token in the URL fragment: #recover?token=XXX
    Token expires in 60 minutes.
    """
    name = full_name or "there"
    recovery_url = f"{APP_URL}/#recover?token={recovery_token}"
    subject = "Recover your ShieldScan account"

    content = f"""
      <h2 style="margin:0 0 16px;color:#fff;font-size:22px;font-weight:600;">
        Recover your account
      </h2>
      <p style="margin:0 0 16px;font-size:15px;line-height:1.6;color:#9496b0;">
        Hi {name}, we received a request to recover your ShieldScan account.
      </p>

      <!-- Warning box -->
      <div style="background:#1c1a10;border:1px solid #854d0e;border-radius:8px;
                  padding:16px 20px;margin:0 0 24px;">
        <p style="margin:0;font-size:13px;color:#fbbf24;line-height:1.6;">
          ⏱ Your account is scheduled for permanent deletion after the 30-day grace period.<br>
          Clicking the button below will <strong>immediately reactivate</strong> your account
          and cancel the deletion.
        </p>
      </div>

      <!-- CTA button -->
      <div style="text-align:center;margin:0 0 28px;">
        <a href="{recovery_url}"
           style="display:inline-block;padding:14px 36px;
                  background:linear-gradient(135deg,#10b981,#059669);
                  color:#fff;text-decoration:none;border-radius:8px;
                  font-size:15px;font-weight:600;letter-spacing:0.3px;">
          Recover My Account
        </a>
      </div>

      <p style="margin:0 0 12px;font-size:13px;color:#555775;">
        This link expires in <strong style="color:#fff;">60 minutes</strong>.
        If you didn't request account recovery, you can safely ignore this email
        — your account will still be deleted after the grace period.
      </p>
      <p style="margin:0;font-size:12px;color:#6c63ff;word-break:break-all;
                background:#12141f;padding:12px;border-radius:6px;font-family:'Courier New',monospace;">
        {recovery_url}
      </p>
    """

    text = f"""
ShieldScan — Account Recovery

Hi {name},

Click the link below to recover your ShieldScan account (valid for 60 minutes):

{recovery_url}

This will immediately reactivate your account and cancel the pending deletion.

If you didn't request recovery, ignore this email. Your account remains scheduled for deletion.
"""

    _send(to_email, subject, _base_html(content), text)


def is_email_configured() -> bool:
    """Used by health-check endpoint to surface email status."""
    return _is_configured()

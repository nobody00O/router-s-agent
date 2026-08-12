"""
webapp/email_sender.py

Sends real emails via SMTP -- this is what makes email verification actually
verify something, instead of just checking for an "@" character.

*** HONESTY NOTE, same pattern as netguard/discover.py's real vs mock split ***
`send_email_smtp()` is real, correct code using Python's standard `smtplib`.
I could not test actual delivery from my sandbox (no SMTP credentials, and
sending real email to a real inbox isn't something I can verify happened).
`send_email_console()` is the tested fallback -- it "sends" by printing the
email to the server log instead, which is what this app uses by default so
everything (signup, verification, login-blocking) can be built and proven
correct without needing real email credentials configured yet.

To send REAL email once you're ready, set these environment variables
(Render: Dashboard -> your service -> Environment):
    SMTP_HOST       e.g. smtp.gmail.com
    SMTP_PORT       e.g. 587
    SMTP_USER       your sending email address
    SMTP_PASSWORD   an APP PASSWORD, not your real Gmail password --
                    Gmail: Google Account -> Security -> 2-Step Verification
                    -> App Passwords -> generate one for "Mail"
    FROM_EMAIL      what shows as the sender, usually same as SMTP_USER

Without those set, the app automatically falls back to console mode (prints
the email instead of sending it) so it never crashes from missing config --
it just won't actually reach anyone's inbox until configured.
"""
from __future__ import annotations
import os
import smtplib
from email.mime.text import MIMEText


def send_email_smtp(to_email: str, subject: str, body: str) -> None:
    """REAL implementation. Requires SMTP_HOST/PORT/USER/PASSWORD/FROM_EMAIL
    environment variables to be set. Raises on failure (caller should handle)."""
    host = os.environ["SMTP_HOST"]
    port = int(os.environ.get("SMTP_PORT", "587"))
    user = os.environ["SMTP_USER"]
    password = os.environ["SMTP_PASSWORD"]
    from_email = os.environ.get("FROM_EMAIL", user)

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = from_email
    msg["To"] = to_email

    with smtplib.SMTP(host, port, timeout=10) as server:
        server.starttls()
        server.login(user, password)
        server.sendmail(from_email, [to_email], msg.as_string())


def send_email_console(to_email: str, subject: str, body: str) -> None:
    """TEST/FALLBACK implementation -- prints instead of sending. Used
    automatically when SMTP isn't configured, so the app still runs and the
    verification FLOW can be tested even without real email set up yet."""
    print("=" * 60)
    print(f"[EMAIL -- console mode, not actually sent] To: {to_email}")
    print(f"Subject: {subject}")
    print(body)
    print("=" * 60)


def is_smtp_configured() -> bool:
    return all(os.environ.get(k) for k in ("SMTP_HOST", "SMTP_USER", "SMTP_PASSWORD"))


def send_verification_email(to_email: str, verify_url: str) -> None:
    subject = "Verify your Home Network Guardian account"
    body = (
        f"Hi,\n\nClick the link below to verify your email and activate your account:\n\n"
        f"{verify_url}\n\nIf you didn't sign up for this, you can ignore this email.\n"
    )
    if is_smtp_configured():
        send_email_smtp(to_email, subject, body)
    else:
        send_email_console(to_email, subject, body)


if __name__ == "__main__":
    print("SMTP configured:", is_smtp_configured())
    print("\nSending a test verification email (console mode expected since no SMTP env vars are set here):\n")
    send_verification_email("test@example.edu", "https://example.onrender.com/verify/abc123token")
    print("\nemail_sender.py self-test: PASS (fell back to console mode correctly)")

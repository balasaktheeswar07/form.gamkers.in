import hashlib
import re
import secrets

from cryptography.fernet import Fernet, InvalidToken
from email_validator import EmailNotValidError, validate_email
from flask import current_app


def new_token():
    return secrets.token_urlsafe(32)


def hash_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def encrypt_smtp_password(password):
    key = current_app.config.get("SMTP_ENCRYPTION_KEY")
    if not key:
        raise RuntimeError("Set SMTP_ENCRYPTION_KEY before saving SMTP credentials.")
    try:
        return Fernet(key.encode("ascii")).encrypt(password.encode("utf-8")).decode("ascii")
    except (ValueError, TypeError) as error:
        raise RuntimeError("SMTP_ENCRYPTION_KEY must be a valid Fernet key.") from error


def decrypt_smtp_password(encrypted):
    key = current_app.config.get("SMTP_ENCRYPTION_KEY")
    if not key:
        raise RuntimeError("Set SMTP_ENCRYPTION_KEY before sending organization email.")
    try:
        return Fernet(key.encode("ascii")).decrypt(encrypted.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, TypeError) as error:
        raise RuntimeError("Unable to decrypt SMTP credentials; verify SMTP_ENCRYPTION_KEY.") from error


def valid_email(value):
    if not value or len(value) > 255:
        return False
    try:
        validate_email(value, check_deliverability=False)
        return True
    except EmailNotValidError:
        return False


_SAMESITE_ATTRIBUTE = re.compile(r";\s*samesite\s*=", re.IGNORECASE)
_VALID_SAMESITE = {"lax": "Lax", "strict": "Strict", "none": "None"}


class EnforceCookieAttributes:
    """WSGI backstop: guarantee every ``Set-Cookie`` header carries ``SameSite``.

    Flask finalises the session cookie, and Flask-Login its remember-me cookie,
    *after* ``after_request`` hooks run, so a hook cannot see them. Wrapping the
    WSGI app sees every cookie that actually leaves the process, whichever code
    path (or future ``response.set_cookie`` call) produced it. Browsers that
    default a missing ``SameSite`` to ``None`` would otherwise send such a cookie
    on cross-site requests (CSRF exposure). An explicit ``SameSite`` is never
    overridden.
    """

    def __init__(self, wsgi_app, default_samesite="Lax"):
        self.wsgi_app = wsgi_app
        self.default_samesite = _VALID_SAMESITE.get(
            str(default_samesite or "Lax").lower(), "Lax"
        )

    def _patch(self, cookie):
        if _SAMESITE_ATTRIBUTE.search(cookie):
            return cookie
        return f"{cookie}; SameSite={self.default_samesite}"

    def __call__(self, environ, start_response):
        def patched_start_response(status, headers, exc_info=None):
            headers = [
                (name, self._patch(value)) if name.lower() == "set-cookie" else (name, value)
                for name, value in headers
            ]
            return start_response(status, headers, exc_info)

        return self.wsgi_app(environ, patched_start_response)
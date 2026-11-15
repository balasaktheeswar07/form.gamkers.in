import threading
from datetime import timedelta

from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy import func

from app.extensions import db, limiter
from app.mail import send_email
from app.auth.models import Invitation, PasswordReset, User
from app.security import hash_token, new_token, valid_email
from app.urls import absolute_app_url
from app.utils import utcnow

auth = Blueprint("auth", __name__)

PASSWORD_RESET_TTL = timedelta(minutes=30)
# Per-account cap on reset emails, enforced from the database so it holds across
# worker processes (the in-memory limiter store is per-process) and across IPs.
PASSWORD_RESET_MAX_PER_HOUR = 3


@auth.route("/login", methods=["GET", "POST"])
@auth.route("/admin/login", methods=["GET", "POST"])  # registered first: url_for() builds this one
@limiter.limit("10 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = db.session.scalar(db.select(User).where(User.email == email))
        password = request.form.get("password", "")
        if user and len(password) <= 1024 and user.check_password(password):
            login_user(user, remember=request.form.get("remember") == "on")
            next_url = request.args.get("next", "")
            if next_url.startswith("/") and not next_url.startswith("//") and "\\" not in next_url:
                return redirect(next_url)
            return redirect(url_for("main.dashboard"))
        flash("Email or password is incorrect.", "error")
    return render_template("auth/login.html")


@auth.post("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("main.home"))


def _issue_password_reset(email):
    """Create a reset token for ``email`` and mail it, if the account exists.

    Runs outside the request/response path (see ``_dispatch_password_reset``) so the
    HTTP response never depends on whether the account exists, how busy the database
    is, or how long SMTP takes. Never raises.
    """
    try:
        user = db.session.scalar(db.select(User).where(User.email == email))
        if not user:
            return
        # PasswordReset has no created_at; expires_at is always created + TTL, so a
        # row created in the last hour has expires_at > now - 1h + TTL.
        recent = db.session.scalar(
            db.select(func.count(PasswordReset.id)).where(
                PasswordReset.user_id == user.id,
                PasswordReset.expires_at > utcnow() - timedelta(hours=1) + PASSWORD_RESET_TTL,
            )
        )
        if recent >= PASSWORD_RESET_MAX_PER_HOUR:
            current_app.logger.warning("Password reset throttled for user id %s.", user.id)
            return
        PasswordReset.query.filter_by(user_id=user.id, used_at=None).update(
            {"used_at": utcnow()}, synchronize_session=False
        )
        token = new_token()
        db.session.add(
            PasswordReset(
                user_id=user.id,
                token_hash=hash_token(token),
                expires_at=utcnow() + PASSWORD_RESET_TTL,
            )
        )
        db.session.commit()
        link = absolute_app_url("auth.reset_password", token=token)
        if not send_email(
            user.email,
            "Reset your GAMKERS PORTAL password",
            f"Reset your password within 30 minutes:\n\n{link}",
            user.organization,
        ):
            current_app.logger.warning("Password reset email not sent: no SMTP configuration.")
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Password reset processing failed.")


def _dispatch_password_reset(email):
    """Hand the reset work off so every valid-looking request returns equally fast."""
    app = current_app._get_current_object()
    if app.config.get("PASSWORD_RESET_INLINE_DELIVERY", app.testing):
        _issue_password_reset(email)
        return

    def run():
        # url_for() needs a request context when SERVER_NAME is unset.
        with app.app_context(), app.test_request_context():
            try:
                _issue_password_reset(email)
            finally:
                db.session.remove()

    threading.Thread(target=run, name="password-reset", daemon=True).start()


@auth.route("/forgot-password", methods=["GET", "POST"])
@limiter.limit("5 per hour;20 per day", methods=["POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if valid_email(email):
            _dispatch_password_reset(email)
        # Same response whether or not the account exists, was throttled, or failed.
        flash("If an account matches that email, a password reset link will be sent.", "info")
        return redirect(url_for("auth.forgot_password"))
    return render_template("auth/forgot_password.html")


@auth.route("/reset-password/<token>", methods=["GET", "POST"])
@limiter.limit("10 per hour")
def reset_password(token):
    reset = db.session.scalar(
        db.select(PasswordReset).where(PasswordReset.token_hash == hash_token(token))
    )
    if not reset or reset.used_at or reset.expires_at <= utcnow():
        flash("This password reset link is invalid or has expired.", "error")
        return redirect(url_for("auth.forgot_password"))
    if request.method == "POST":
        password = request.form.get("password", "")
        if not 12 <= len(password) <= 1024:
            flash("Use a password with 12–1,024 characters.", "error")
        else:
            user = db.session.get(User, reset.user_id)
            user.set_password(password)
            reset.used_at = utcnow()
            db.session.commit()
            flash("Your password has been updated. Please sign in.", "success")
            return redirect(url_for("auth.login"))
    return render_template("auth/reset_password.html")


@auth.route("/invite/<token>", methods=["GET", "POST"])
@limiter.limit("10 per hour")
def accept_invitation(token):
    invitation = db.session.scalar(
        db.select(Invitation).where(Invitation.token_hash == hash_token(token))
    )
    if not invitation or invitation.accepted_at or invitation.expires_at <= utcnow():
        flash("This invitation is invalid or has expired.", "error")
        return redirect(url_for("auth.login"))
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        password = request.form.get("password", "")
        if not name or len(name) > 120 or not 12 <= len(password) <= 1024:
            flash("Enter your name and a password with 12–1,024 characters.", "error")
        elif db.session.scalar(db.select(User.id).where(func.lower(User.email) == invitation.email)):
            flash("An account already exists for this email address.", "error")
        else:
            user = User(
                organization_id=invitation.organization_id,
                email=invitation.email,
                name=name,
                role=invitation.role,
            )
            user.set_password(password)
            invitation.accepted_at = utcnow()
            db.session.add(user)
            db.session.commit()
            login_user(user)
            return redirect(url_for("main.dashboard"))
    return render_template("auth/accept_invitation.html", invitation=invitation)

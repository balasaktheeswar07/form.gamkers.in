"""Hardening tests for /forgot-password (MED-04: rate limiting and enumeration)."""
import threading
import time

import pytest

from app import create_app
from app.extensions import db, limiter
from app.models import Organization, PasswordReset, User

KNOWN = "alex@example.com"
UNKNOWN = "nobody@example.com"
MESSAGE = b"If an account matches that email"


def _make_app(tmp_path, **overrides):
    config = {
        "TESTING": True,
        "SECRET_KEY": "test-key-not-for-production",
        "APPLICATION_BASE_URL": "https://forms.example",
        "SQLALCHEMY_DATABASE_URI": "sqlite://",
        "CERTIFICATE_STORAGE_PATH": str(tmp_path / "certificates"),
        "CERTIFICATE_UPLOAD_PATH": str(tmp_path / "certificate-uploads"),
        "FORM_BANNER_STORAGE_PATH": str(tmp_path / "form-banners"),
        "TEAM_PHOTO_STORAGE_PATH": str(tmp_path / "team-photos"),
        "WTF_CSRF_ENABLED": False,
        "RATELIMIT_ENABLED": False,
        "RATELIMIT_STORAGE_URI": "memory://",
        "SMTP_ENCRYPTION_KEY": None,
        "DEFAULT_SMTP_HOST": None,
        "DEFAULT_SMTP_SENDER": None,
        "HOSTINGER_MAIL_API_TOKEN": None,
    }
    config.update(overrides)
    return create_app(config)


def _seed_user(email=KNOWN):
    organization = Organization(name="Northstar Labs")
    user = User(name="Alex", email=email, role="admin", organization=organization)
    user.set_password("old-password-that-is-long")
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture
def limited_app(tmp_path):
    app = _make_app(tmp_path, RATELIMIT_ENABLED=True)
    with app.app_context():
        db.create_all()
        limiter.reset()
        _seed_user()
        yield app
        limiter.reset()
        db.session.remove()
        db.drop_all()


def test_forgot_password_post_is_rate_limited_per_ip(limited_app, monkeypatch):
    monkeypatch.setattr("app.auth.routes.send_email", lambda *a: True)
    client = limited_app.test_client()
    for _ in range(5):
        response = client.post("/forgot-password", data={"email": UNKNOWN})
        assert response.status_code == 302
        assert response.headers["X-RateLimit-Limit"] == "5"
    blocked = client.post("/forgot-password", data={"email": UNKNOWN})
    assert blocked.status_code == 429
    assert blocked.headers["Retry-After"]


def test_rate_limit_does_not_depend_on_whether_the_email_exists(limited_app, monkeypatch):
    monkeypatch.setattr("app.auth.routes.send_email", lambda *a: True)
    client = limited_app.test_client()
    statuses = [
        client.post("/forgot-password", data={"email": KNOWN if i % 2 else UNKNOWN}).status_code
        for i in range(7)
    ]
    assert statuses == [302] * 5 + [429] * 2


def test_viewing_the_form_does_not_consume_the_submission_budget(limited_app, monkeypatch):
    monkeypatch.setattr("app.auth.routes.send_email", lambda *a: True)
    client = limited_app.test_client()
    for _ in range(10):
        assert client.get("/forgot-password").status_code == 200
    assert client.post("/forgot-password", data={"email": UNKNOWN}).status_code == 302


def test_response_is_identical_for_known_and_unknown_accounts(app, client, monkeypatch):
    with app.app_context():
        _seed_user()
    monkeypatch.setattr("app.auth.routes.send_email", lambda *a: True)
    known = client.post("/forgot-password", data={"email": KNOWN}, follow_redirects=True)
    unknown = client.post("/forgot-password", data={"email": UNKNOWN}, follow_redirects=True)
    malformed = client.post("/forgot-password", data={"email": "not-an-email"}, follow_redirects=True)
    for response in (known, unknown, malformed):
        assert response.status_code == 200
        assert MESSAGE in response.data
    first = client.post("/forgot-password", data={"email": KNOWN})
    second = client.post("/forgot-password", data={"email": UNKNOWN})
    assert first.status_code == second.status_code == 302
    assert first.headers["Location"] == second.headers["Location"]


def test_per_account_throttle_caps_reset_emails_without_changing_the_response(
    app, client, monkeypatch
):
    with app.app_context():
        user_id = _seed_user().id
    sent = []
    monkeypatch.setattr("app.auth.routes.send_email", lambda *a: sent.append(a) or True)
    responses = [client.post("/forgot-password", data={"email": KNOWN}) for _ in range(6)]
    assert {r.status_code for r in responses} == {302}  # nothing reveals the throttle
    assert len(sent) == 3
    with app.app_context():
        assert PasswordReset.query.filter_by(user_id=user_id).count() == 3
        assert PasswordReset.query.filter_by(user_id=user_id, used_at=None).count() == 1


def test_delivery_runs_off_the_request_path(tmp_path, monkeypatch):
    app = _make_app(tmp_path, PASSWORD_RESET_INLINE_DELIVERY=False)
    started, release = threading.Event(), threading.Event()

    def slow_send(*args):
        started.set()
        release.wait(5)  # stand-in for a slow SMTP server
        return True

    monkeypatch.setattr("app.auth.routes.send_email", slow_send)
    with app.app_context():
        db.create_all()
        user_id = _seed_user().id
        client = app.test_client()
        began = time.monotonic()
        response = client.post("/forgot-password", data={"email": KNOWN})
        elapsed = time.monotonic() - began
        # The response must not wait for SMTP, so it can't leak existence via timing.
        assert response.status_code == 302
        assert not release.is_set() and elapsed < 2
        assert started.wait(5)
        release.set()
        for thread in threading.enumerate():
            if thread.name == "password-reset":
                thread.join(5)
        db.session.remove()
        assert PasswordReset.query.filter_by(user_id=user_id).count() == 1
        db.session.remove()
        db.drop_all()
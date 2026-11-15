"""HIGH-03 regression: every cookie the app emits must carry SameSite."""

ADMIN = {"name": "Alex Admin", "email": "admin@example.com", "password": "a-very-long-password"}


def _create_admin(app):
    result = app.test_cli_runner().invoke(
        args=["create-admin", "--name", ADMIN["name"], "--email", ADMIN["email"]],
        input=f"{ADMIN['password']}\n{ADMIN['password']}\n",
    )
    assert result.exit_code == 0, result.output


def test_public_and_login_pages_never_emit_a_cookie_without_samesite(client, app):
    _create_admin(app)
    for path in ["/", "/admin/login"]:
        response = client.get(path, base_url="https://localhost")
        assert response.status_code == 200
        for cookie in response.headers.getlist("Set-Cookie"):
            assert "samesite=" in cookie.lower(), cookie


def test_session_and_remember_cookies_use_lax_samesite(client, app):
    _create_admin(app)
    response = client.post(
        "/admin/login",
        data={**{"email": ADMIN["email"], "password": ADMIN["password"]}, "remember": "on"},
        base_url="https://localhost",
    )
    cookies = response.headers.getlist("Set-Cookie")
    assert response.status_code == 302
    assert any(cookie.startswith("session=") for cookie in cookies), cookies
    assert any(cookie.startswith("remember_token=") for cookie in cookies), cookies
    for cookie in cookies:
        assert "samesite=lax" in cookie.lower(), cookie

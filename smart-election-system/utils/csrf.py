"""Session-backed CSRF tokens for POST forms."""

import secrets

from flask import request, session


def ensure_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


def regenerate_csrf_token():
    session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


def validate_csrf_form():
    token = request.form.get("csrf_token")
    return bool(token and token == session.get("csrf_token"))

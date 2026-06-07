import os

from dotenv import load_dotenv
from flask import Flask, render_template, session

from db import init_db


def create_app():
    load_dotenv()

    app = Flask(__name__)
    secret = os.environ.get("SECRET_KEY")
    if not secret:
        secret = "dev-insecure-change-me"
        app.logger.warning("SECRET_KEY missing; using insecure development default.")
    app.secret_key = secret

    from blueprints.admin import bp as admin_bp
    from blueprints.auth import bp as auth_bp
    from blueprints.public import bp as public_bp
    from blueprints.voter import bp as voter_bp

    app.register_blueprint(public_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(voter_bp)
    app.register_blueprint(auth_bp)

    @app.before_request
    def _ensure_csrf():
        from utils.csrf import ensure_csrf_token

        ensure_csrf_token()

    @app.context_processor
    def _inject_csrf():
        return {"csrf_token": session.get("csrf_token")}

    @app.context_processor
    def _inject_nav():
        return {
            "is_voter": bool(session.get("user_id")),
            "is_admin": bool(session.get("election_id")),
            "voter_status": session.get("voter_status"),
        }

    @app.errorhandler(404)
    def not_found(_exc):
        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def server_error(_exc):
        return render_template("errors/500.html"), 500

    return app


def bootstrap_schema():
    """Create DB tables if missing (CLI / __main__)."""
    init_db()

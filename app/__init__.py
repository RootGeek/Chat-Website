import os
import secrets
from pathlib import Path

from flask import Flask, g, render_template, session, redirect, url_for
from flask_login import LoginManager, current_user, logout_user, user_logged_in, user_logged_out
from flask_socketio import SocketIO
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError, generate_csrf
from dotenv import load_dotenv

from . import config
from . import models

# Lade .env (frühzeitig!)
load_dotenv()

# Extensions
login_manager = LoginManager()
socketio = SocketIO()
csrf = CSRFProtect()

class CsrfTokenProxy:
    def __call__(self):
        return generate_csrf()
    def __str__(self):
        return generate_csrf()

def create_app():
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object("app.config")

    # SECRET_KEY setzen – aus .env oder config oder persistentem Instance-File
    env_secret_key = os.environ.get("SECRET_KEY")
    if env_secret_key:
        app.config["SECRET_KEY"] = env_secret_key
    else:
        candidate = getattr(config, "SECRET_KEY", None)
        if not candidate or candidate.strip() == "change-me-to-a-secure-random-string":
            # versuche aus instance/SECRET_KEY zu lesen oder generiere neuen
            instance_dir = Path(app.instance_path)
            instance_dir.mkdir(parents=True, exist_ok=True)
            key_file = instance_dir / "SECRET_KEY"
            if key_file.exists():
                candidate = key_file.read_text(encoding="utf-8").strip()
            else:
                candidate = secrets.token_urlsafe(32)
                key_file.write_text(candidate, encoding="utf-8")
        app.config["SECRET_KEY"] = candidate

    # Für HTTPS: Session-Cookies nur über verschlüsselte Verbindung zulassen – Standard aus config.py respektieren
    app.config.setdefault("SESSION_COOKIE_SECURE", not app.config.get("DEBUG", False))
    app.config.setdefault("REMEMBER_COOKIE_SECURE", not app.config.get("DEBUG", False))# Für HTTPS: Session-Cookies nur über verschlüsselte Verbindung zulassen
    app.config["SESSION_COOKIE_SECURE"] = True
    app.config["REMEMBER_COOKIE_SECURE"] = True

    # Fallbacks / sichere Defaults für alles andere
    app.config.setdefault("SESSION_COOKIE_HTTPONLY", True)
    app.config.setdefault("SESSION_COOKIE_SAMESITE", "Lax")
    app.config.setdefault("REMEMBER_COOKIE_SAMESITE", "Lax")

    # Instance-Ordner / DB-Pfad sicherstellen
    db_parent = Path(app.config["DATABASE_PATH"]).parent
    db_parent.mkdir(parents=True, exist_ok=True)

    # Init extensions
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message_category = "error"
    login_manager.session_protection = "strong"
    socketio.init_app(app, manage_session=False)
    csrf.init_app(app)

    # Blueprints registrieren
    from .auth import bp as auth_bp
    from .chat import bp as chat_bp
    from .admin import bp as admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(chat_bp)
    app.register_blueprint(admin_bp)

    # Datenbank initialisieren (idempotent)
    models.init_db(app)

    # Context processor für CSRF und CSP nonce
    @app.context_processor
    def inject_csrf_and_nonce():
        nonce = secrets.token_urlsafe(16)
        g.csp_nonce = nonce
        return {
            "csrf_token": CsrfTokenProxy(),
            "csp_nonce": nonce,
        }

    # Security Headers setzen
    @app.after_request
    def set_security_headers(response):
        nonce = getattr(g, "csp_nonce", "")
        csp = (
            "default-src 'self'; "
            f"script-src 'nonce-{nonce}' https://cdn.socket.io https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none';"
        )
        response.headers.setdefault("Content-Security-Policy", csp)
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload"
        )
        response.headers.setdefault("Permissions-Policy", "interest-cohort=()")
        response.headers.setdefault("X-Permitted-Cross-Domain-Policies", "none")
        return response

    # Root redirect
    @app.route("/")
    def index():
        if current_user.is_authenticated:
            return redirect(url_for("chat.chatroom"))
        return redirect(url_for("auth.login"))

    # Single-session enforcement
    @app.before_request
    def enforce_single_session():
        if current_user.is_authenticated:
            token_session = session.get("session_token")
            db_token = models.get_session_token(int(current_user.get_id()))
            if not token_session or not db_token or token_session != db_token:
                logout_user()

    # User loader für Flask-Login
    @login_manager.user_loader
    def load_user(user_id):
        try:
            return models.get_user_by_id(int(user_id))
        except Exception:
            return None

    # Nach Login: neuen session token setzen + tägliche Aktivität
    @user_logged_in.connect_via(app)
    def on_user_logged_in(sender, user):
        token = secrets.token_urlsafe(32)
        try:
            models.set_session_token(int(user.get_id()), token)
        except Exception:
            pass
        session["session_token"] = token
        try:
            models.record_daily_activity(int(user.get_id()))
        except Exception:
            pass

    # Nach Logout: token entfernen
    @user_logged_out.connect_via(app)
    def on_user_logged_out(sender, user):
        try:
            models.clear_session_token(int(user.get_id()))
        except Exception:
            pass
        session.pop("session_token", None)

    # CSRF Error Handler
    @app.errorhandler(CSRFError)
    def handle_csrf(e):
        return render_template("csrf_error.html", reason=e.description), 400

    return app, socketio

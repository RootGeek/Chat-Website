import logging
from functools import wraps

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, current_app
from flask_login import login_required, current_user
from flask_socketio import join_room

from . import models, socketio
from .chat import online_users

bp = Blueprint("admin", __name__, url_prefix="/admin")
logger = logging.getLogger(__name__)


def admin_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not getattr(current_user, "is_admin", False):
            flash("Keine Berechtigung.", "error")
            return redirect(url_for("chat.chatroom"))
        return f(*args, **kwargs)

    return wrapped


def _load_all_users():
    try:
        db = models.get_db()
        rows = db.execute(
            "SELECT id, username, is_admin, is_blocked, ban_reason, strike_count FROM users ORDER BY username ASC"
        ).fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        logger.exception("Failed to load users: %s", e)
        return []


def broadcast_user_changes():
    users = _load_all_users()
    socketio.emit("users_update", {"users": users}, to="admins")


@bp.route("/", methods=["GET"])
@login_required
@admin_required
def dashboard():
    users = _load_all_users()
    return render_template("admin.html", users=users)


@bp.route("/create_user", methods=["POST"])
@login_required
@admin_required
def create_user():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    is_admin_flag = bool(request.form.get("is_admin"))
    if not username or not password:
        flash("Benutzername und Passwort erforderlich.", "error")
        return redirect(url_for("admin.dashboard"))

    if len(username) > 64 or len(password) < 8:
        flash("Benutzername zu lang oder Passwort zu kurz (mindestens 8 Zeichen).", "error")
        return redirect(url_for("admin.dashboard"))

    try:
        success = models.create_user(username, password, is_admin=is_admin_flag)
    except Exception as e:
        logger.exception("Error creating user %s: %s", username, e)
        success = False

    if not success:
        flash("Benutzername bereits vorhanden oder Fehler beim Erstellen.", "error")
    else:
        flash(f"Benutzer '{username}' erstellt.", "success")
        broadcast_user_changes()
    return redirect(url_for("admin.dashboard"))


@bp.route("/block/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def block(user_id):
    if int(user_id) == int(current_user.get_id()):
        flash("Du kannst dich nicht selbst sperren.", "error")
        return redirect(url_for("admin.dashboard"))

    reason = request.form.get("reason", "Keine Angabe.")
    try:
        models.block_user(user_id, reason)
    except Exception as e:
        logger.exception("Error blocking user %s: %s", user_id, e)
        flash("Fehler beim Sperren des Benutzers.", "error")
        return redirect(url_for("admin.dashboard"))

    # Sofortige Abmeldung, wenn online
    entry = online_users.get(str(user_id))
    if entry:
        for sid in list(entry.get("sids", [])):
            socketio.emit("show_popup", {"message": "Du wurdest vom Admin gesperrt."}, to=sid)
            socketio.emit("redirect", {"url": "/auth/banned"}, to=sid)

    flash(f"Benutzer gesperrt: {reason}", "success")
    broadcast_user_changes()
    return redirect(url_for("admin.dashboard"))


@bp.route("/unblock/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def unblock(user_id):
    try:
        models.unblock_user(user_id)
    except Exception as e:
        logger.exception("Error unblocking user %s: %s", user_id, e)
        flash("Fehler beim Entsperren des Benutzers.", "error")
        return redirect(url_for("admin.dashboard"))
    flash("Benutzer entsperrt.", "success")
    broadcast_user_changes()
    return redirect(url_for("admin.dashboard"))


@bp.route("/reset_strikes/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def reset_strikes(user_id):
    try:
        models.reset_strikes(user_id)
    except Exception as e:
        logger.exception("Error resetting strikes for user %s: %s", user_id, e)
        flash("Fehler beim Zurücksetzen der Strikes.", "error")
        return redirect(url_for("admin.dashboard"))
    flash("Strikes zurückgesetzt.", "success")
    broadcast_user_changes()
    return redirect(url_for("admin.dashboard"))


@bp.route("/delete_user/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def delete_user(user_id):
    if int(user_id) == int(current_user.get_id()):
        flash("Du kannst dich nicht selbst löschen.", "error")
        return redirect(url_for("admin.dashboard"))
    try:
        success = models.delete_user(user_id)
    except Exception as e:
        logger.exception("Error deleting user %s: %s", user_id, e)
        success = False

    if success:
        flash("Benutzer gelöscht.", "success")
    else:
        flash("Benutzer nicht gefunden oder Fehler.", "error")
    broadcast_user_changes()
    return redirect(url_for("admin.dashboard"))


@bp.route("/metrics/active_users")
@login_required
@admin_required
def active_users_metrics():
    days = request.args.get("days", default=30, type=int)
    if days < 1 or days > 365:
        return jsonify({"error": "Invalid days parameter"}), 400
    try:
        data = models.get_daily_active_counts(days=days)
    except Exception as e:
        logger.exception("Error fetching active users metrics: %s", e)
        return jsonify({"error": "Failed to fetch metrics"}), 500
    return jsonify(data)


@bp.route("/metrics/online_now")
@login_required
@admin_required
def online_now():
    try:
        count = len(online_users)
    except Exception:
        count = 0
    return jsonify({"online_now": count})


@bp.route("/users_json")
@login_required
@admin_required
def users_json():
    users = _load_all_users()
    return jsonify(users)


@socketio.on("admin_ui_connect")
def handle_admin_ui_connect(auth=None):
    if not getattr(current_user, "is_authenticated", False) or not getattr(current_user, "is_admin", False):
        return False
    join_room("admins")
    users = _load_all_users()
    socketio.emit("users_update", {"users": users}, to="admins")

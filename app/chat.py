import re
import time
from datetime import datetime
from flask import Blueprint, render_template, request, jsonify, session, current_app
from flask_login import login_required, current_user
from flask_socketio import emit, disconnect as socketio_disconnect

from . import socketio, models

bp = Blueprint("chat", __name__, url_prefix="/chat")

# Online users: key = str(user_id), value = {"username": ..., "sids": set([...])}
online_users = {}

# Spam / repeat tracking / mute state
_USER_MESSAGE_TIMES = {}  # user_id_str -> list of timestamps
_LAST_MESSAGE = {}  # user_id_str -> {"text": ..., "time": timestamp}
_MUTE_UNTIL = {}  # user_id_str -> timestamp until which user is muted

# Configuration constants
SPAM_WINDOW = 10  # seconds
SPAM_LIMIT = 5  # messages in window
REPEAT_THRESHOLD_SEC = 2  # identical within this = mute
MUTE_DURATION = 15  # seconds
MAX_MESSAGE_LENGTH = 2000  # cap message length

URL_PATTERN = re.compile(r"(https?://[^\s]+|www\.[^\s]+|\b[0-9a-zA-Z]{16,56}\.onion\b)", re.IGNORECASE)
MENTION_PATTERN = re.compile(r"/([A-Za-z0-9_]+)")


@bp.route("/")
@login_required
def chatroom():
    user = current_user
    return render_template(
        "chat.html",
        username=user.username,
        is_admin=user.is_admin,
    )


@bp.route("/history")
@login_required
def history():
    since_id = request.args.get("since_id", default=0, type=int)
    msgs = models.get_messages_since(since_id)
    return jsonify(msgs)


def _broadcast_user_list():
    users = [info["username"] for info in online_users.values()]
    socketio.emit("user_list", {"users": users})


def _send_popup(sid, message):
    socketio.emit("show_popup", {"message": message}, to=sid)


def _redirect(sid, url):
    socketio.emit("redirect", {"url": url}, to=sid)


def _handle_blocked_sid(sid, reason):
    _send_popup(sid, f"You are banned: {reason or 'No reason provided.'}")
    target = "/auth/banned"
    if reason:
        from urllib.parse import quote

        target = f"/auth/banned?reason={quote(reason)}"
    _redirect(sid, target)
    try:
        socketio_disconnect(sid)
    except Exception:
        current_app.logger.debug(f"Failed to disconnect SID {sid} after block.")


def _is_session_valid():
    from flask import session as flask_session

    if not current_user.is_authenticated:
        return False
    token_session = flask_session.get("session_token")
    db_token = models.get_session_token(int(current_user.get_id()))
    return bool(token_session and db_token and token_session == db_token)


def _apply_strike_and_maybe_block(user_obj, reason_for_block, mute_message_template, uid_str, now):
    """
    Erhöht Strikes, behandelt Mute / Block und gibt Status zurück.
    Rückgabe: tuple (blocked: bool, muted: bool, strikes: int)
    """
    strikes = models.increment_strike(int(user_obj.get_id()))
    if strikes is None:
        strikes = 0
    sids = list(online_users.get(uid_str, {}).get("sids", []))

    if strikes >= 3:
        # blockieren
        models.block_user(int(user_obj.get_id()), reason_for_block)
        for sid in sids:
            _handle_blocked_sid(sid, reason_for_block)
        current_app.logger.info(f"User {user_obj.username} blocked for: {reason_for_block}")
        return True, False, strikes
    else:
        # temporär stummschalten
        _MUTE_UNTIL[uid_str] = now + MUTE_DURATION
        for sid in sids:
            _send_popup(
                sid,
                mute_message_template.format(strikes=strikes, duration=MUTE_DURATION),
            )
        return False, True, strikes


@socketio.on("connect")
def handle_connect(auth=None):
    if not current_user.is_authenticated or not _is_session_valid():
        return False  # reject anonymous or invalid session
    uid = current_user.get_id()
    username = current_user.username
    sid = request.sid
    if getattr(current_user, "is_blocked", False):
        _handle_blocked_sid(sid, current_user.ban_reason)
        return

    entry = online_users.get(str(uid))
    if entry:
        entry["sids"].add(sid)
    else:
        online_users[str(uid)] = {"username": username, "sids": {sid}}
    _broadcast_user_list()


@socketio.on("disconnect")
def handle_disconnect():
    if not current_user.is_authenticated:
        return
    uid = current_user.get_id()
    sid = request.sid
    entry = online_users.get(str(uid))
    if entry:
        entry["sids"].discard(sid)
        if not entry["sids"]:
            online_users.pop(str(uid), None)
    _broadcast_user_list()


@socketio.on("send_message")
def handle_send_message(data):
    from flask import session as flask_session

    if not current_user.is_authenticated or not _is_session_valid():
        return
    user_obj = current_user
    uid = user_obj.get_id()
    uid_str = str(uid)
    now = time.time()

    # Wenn geblockt, direkt behandeln
    if getattr(user_obj, "is_blocked", False):
        for sid in list(online_users.get(uid_str, {}).get("sids", [])):
            _handle_blocked_sid(sid, user_obj.ban_reason)
        return

    # Wenn noch gemuted
    mute_expires = _MUTE_UNTIL.get(uid_str, 0)
    if now < mute_expires:
        remaining = int(mute_expires - now)
        for sid in list(online_users.get(uid_str, {}).get("sids", [])):
            _send_popup(sid, f"Temporarily muted. {remaining}s remaining.")
        return

    message_text = (data.get("message") or "").strip()
    if not message_text:
        return

    # Nachricht zu lang? Kürzen (Verhindert DoS durch übergroße Payloads)
    if len(message_text) > MAX_MESSAGE_LENGTH:
        message_text = message_text[:MAX_MESSAGE_LENGTH]
        for sid in list(online_users.get(uid_str, {}).get("sids", [])):
            _send_popup(sid, "Message truncated because it was too long.")

    # URL / .onion detection => Strike-System
    if URL_PATTERN.search(message_text):
        blocked, muted, strikes = _apply_strike_and_maybe_block(
            user_obj,
            "Repeated forbidden link posting",
            "Links are forbidden. Strike {strikes}/3. Muted for {duration}s.",
            uid_str,
            now,
        )
        return  # nicht weiter verbreiten

    # Spam: Rate-Limit innerhalb des Fensters
    times = _USER_MESSAGE_TIMES.get(uid_str, [])
    times = [t for t in times if now - t <= SPAM_WINDOW]
    times.append(now)
    _USER_MESSAGE_TIMES[uid_str] = times
    if len(times) > SPAM_LIMIT:
        blocked, muted, strikes = _apply_strike_and_maybe_block(
            user_obj,
            "Spamming",
            "Temporarily muted for spamming ({duration}s). Strike {strikes}/3.",
            uid_str,
            now,
        )
        return

    # Wiederholte identische Nachrichten
    last = _LAST_MESSAGE.get(uid_str)
    if last:
        if message_text == last["text"] and (now - last["time"]) <= REPEAT_THRESHOLD_SEC:
            blocked, muted, strikes = _apply_strike_and_maybe_block(
                user_obj,
                "Repeated identical messages",
                "Temporarily muted for repeated messages ({duration}s). Strike {strikes}/3.",
                uid_str,
                now,
            )
            return

    # Update letzte Nachricht
    _LAST_MESSAGE[uid_str] = {"text": message_text, "time": now}

    # Erwähnungen extrahieren
    mentions = MENTION_PATTERN.findall(message_text)
    mentions_norm = [m for m in mentions]

    # Persistieren
    message_id = models.add_message(user_obj.username, message_text, mentions_norm)

    payload = {
        "id": message_id,
        "from": user_obj.username,
        "message": message_text,
        "mentions": mentions_norm,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }

    socketio.emit("new_message", payload)
    _broadcast_user_list()

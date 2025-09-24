import sqlite3
from flask import current_app, g
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, Any, List

# --- Konfigurationen / Konstanten ---
LOGIN_WINDOW_MINUTES = 15
MAX_FAILURES_BEFORE_LOCK = 5
LOCK_DURATION_SECONDS = 15 * 60  # 15 Minuten
MESSAGE_RETENTION_SECONDS = 48 * 3600  # 48 Stunden
USERNAME_MAX_LENGTH = 150
MESSAGE_MAX_LENGTH = 2000

# Passwort-Context: Argon2id bevorzugt, bcrypt als Fallback. "deprecated=auto" sorgt für Upgrade-Pfade.
pwd_context = CryptContext(
    schemes=["argon2", "bcrypt"],
    deprecated="auto",
    # Optional: feiner tune Argon2-Parameter hier, z.B. time_cost=2, memory_cost=102400, parallelism=8
)

# --- Table Schemas ---
USER_TABLE_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_admin INTEGER DEFAULT 0,
    is_blocked INTEGER DEFAULT 0,
    ban_reason TEXT,
    strike_count INTEGER DEFAULT 0,
    session_token TEXT
);
"""

MESSAGE_TABLE_SCHEMA = """
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    message TEXT NOT NULL,
    mentions TEXT,
    timestamp TEXT NOT NULL
);
"""

ACTIVITY_TABLE_SCHEMA = """
CREATE TABLE IF NOT EXISTS user_activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    day TEXT NOT NULL,
    last_seen TEXT,
    UNIQUE(user_id, day)
);
"""

LOGIN_ATTEMPT_SCHEMA = """
CREATE TABLE IF NOT EXISTS login_attempts (
    username TEXT PRIMARY KEY,
    failure_count INTEGER DEFAULT 0,
    first_failure TEXT,
    lock_until TEXT
);
"""


# --- DB Utility ---
def get_db() -> sqlite3.Connection:
    db = getattr(g, "_database", None)
    if db is None:
        db = sqlite3.connect(
            current_app.config["DATABASE_PATH"],
            check_same_thread=False,
            isolation_level=None,  # Autocommit mode; wir kontrollieren Commit explizit
        )
        db.row_factory = sqlite3.Row
        # Foreign keys aktivieren (SQLite erfordert explizites ON)
        db.execute("PRAGMA foreign_keys = ON")
        g._database = db
    return db


def close_db(e=None):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()
        g._database = None


def init_db(app):
    with app.app_context():
        db = get_db()
        # Tabellen erstellen
        db.execute(USER_TABLE_SCHEMA)
        db.execute(MESSAGE_TABLE_SCHEMA)
        db.execute(ACTIVITY_TABLE_SCHEMA)
        db.execute(LOGIN_ATTEMPT_SCHEMA)

        # Indexe für Performance
        try:
            db.execute("CREATE INDEX IF NOT EXISTS idx_user_activity_day ON user_activity(day)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp)")
        except Exception:
            pass

        # Idempotente Schema-Upgrades (ältere Versionen)
        try:
            db.execute("ALTER TABLE users ADD COLUMN strike_count INTEGER DEFAULT 0")
        except sqlite3.OperationalError:
            pass
        try:
            db.execute("ALTER TABLE users ADD COLUMN session_token TEXT")
        except sqlite3.OperationalError:
            pass

        db.commit()
        app.teardown_appcontext(close_db)


# --- User Management ---
def create_user(username: str, password: str, is_admin: bool = False) -> bool:
    if not username or not password:
        return False
    username = username.strip()
    if len(username) > USERNAME_MAX_LENGTH:
        return False
    pw_hash = pwd_context.hash(password)
    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
            (username, pw_hash, 1 if is_admin else 0),
        )
        db.commit()
        return True
    except sqlite3.IntegrityError:
        return False  # Benutzername schon vergeben
    except Exception as e:
        current_app.logger.exception("create_user failed: %s", e)
        return False


def verify_user(username: str, password: str) -> Tuple[Optional[Dict[str, Any]], str]:
    db = get_db()
    try:
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user:
            if user["is_blocked"]:
                return None, "blocked"
            stored_hash = user["password_hash"]
            try:
                valid = pwd_context.verify(password, stored_hash)
            except Exception:
                return None, "invalid"
            if valid:
                # Upgrade hash bei Bedarf (z.B. bcrypt -> argon2)
                if pwd_context.needs_update(stored_hash):
                    try:
                        new_hash = pwd_context.hash(password)
                        db.execute(
                            "UPDATE users SET password_hash=? WHERE id=?",
                            (new_hash, user["id"]),
                        )
                        db.commit()
                    except Exception:
                        current_app.logger.exception("Password hash upgrade failed for user %s", username)
                return dict(user), None
        return None, "invalid"
    except Exception as e:
        current_app.logger.exception("verify_user error: %s", e)
        return None, "invalid"


def get_user_by_id(user_id: int):
    db = get_db()
    try:
        user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if user:
            return User(dict(user))
    except Exception:
        current_app.logger.exception("get_user_by_id failed")
    return None


def get_user_by_username(username: str):
    db = get_db()
    try:
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user:
            return User(dict(user))
    except Exception:
        current_app.logger.exception("get_user_by_username failed")
    return None


def block_user(user_id: int, reason: str = ""):
    db = get_db()
    try:
        db.execute(
            "UPDATE users SET is_blocked=1, ban_reason=? WHERE id=?",
            (reason, user_id),
        )
        db.commit()
    except Exception:
        current_app.logger.exception("block_user failed for %s", user_id)


def unblock_user(user_id: int):
    db = get_db()
    try:
        db.execute(
            "UPDATE users SET is_blocked=0, ban_reason=NULL, strike_count=0 WHERE id=?",
            (user_id,),
        )
        db.commit()
    except Exception:
        current_app.logger.exception("unblock_user failed for %s", user_id)


def increment_strike(user_id: int) -> Optional[int]:
    db = get_db()
    try:
        user = db.execute("SELECT strike_count FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user:
            return None
        strikes = user["strike_count"] or 0
        strikes += 1
        db.execute("UPDATE users SET strike_count=? WHERE id=?", (strikes, user_id))
        db.commit()
        return strikes
    except Exception:
        current_app.logger.exception("increment_strike failed for %s", user_id)
        return None


def reset_strikes(user_id: int):
    db = get_db()
    try:
        db.execute("UPDATE users SET strike_count=0 WHERE id=?", (user_id,))
        db.commit()
    except Exception:
        current_app.logger.exception("reset_strikes failed for %s", user_id)


# --- Messaging ---
def add_message(username: str, message: str, mentions: Optional[List[str]]):
    if not username or not message:
        return None
    if len(message) > MESSAGE_MAX_LENGTH:
        message = message[:MESSAGE_MAX_LENGTH]
    db = get_db()
    mentions_str = ",".join(mentions) if mentions else ""
    timestamp = datetime.utcnow().isoformat() + "Z"
    try:
        cursor = db.execute(
            "INSERT INTO messages (username, message, mentions, timestamp) VALUES (?, ?, ?, ?)",
            (username, message, mentions_str, timestamp),
        )
        db.commit()
        return cursor.lastrowid
    except Exception:
        current_app.logger.exception("add_message failed for user %s", username)
        return None


def get_messages_since(since_id: int):
    db = get_db()
    try:
        rows = db.execute(
            "SELECT id, username, message, mentions, timestamp FROM messages WHERE id > ? ORDER BY id ASC",
            (since_id,),
        ).fetchall()
        result = []
        for r in rows:
            mentions = r["mentions"].split(",") if r["mentions"] else []
            result.append(
                {
                    "id": r["id"],
                    "from": r["username"],
                    "message": r["message"],
                    "mentions": mentions,
                    "timestamp": r["timestamp"],
                }
            )
        return result
    except Exception:
        current_app.logger.exception("get_messages_since failed")
        return []


# --- Activity Metrics ---
def record_daily_activity(user_id: int):
    db = get_db()
    day = datetime.utcnow().date().isoformat()
    now = datetime.utcnow().isoformat() + "Z"
    try:
        db.execute(
            "INSERT INTO user_activity (user_id, day, last_seen) VALUES (?, ?, ?)",
            (user_id, day, now),
        )
    except sqlite3.IntegrityError:
        db.execute(
            "UPDATE user_activity SET last_seen=? WHERE user_id=? AND day=?",
            (now, user_id, day),
        )
    except Exception:
        current_app.logger.exception("record_daily_activity failed for %s", user_id)
    finally:
        db.commit()


def get_daily_active_counts(days: int = 30):
    db = get_db()
    try:
        today = datetime.utcnow().date()
        start = today - timedelta(days=days - 1)
        rows = db.execute(
            "SELECT day, COUNT(DISTINCT user_id) as cnt FROM user_activity WHERE day >= ? GROUP BY day",
            (start.isoformat(),),
        ).fetchall()
        counts_map = {r["day"]: r["cnt"] for r in rows}
        result = []
        for i in range(days):
            d = (start + timedelta(days=i)).isoformat()
            result.append({"day": d, "count": counts_map.get(d, 0)})
        return result
    except Exception:
        current_app.logger.exception("get_daily_active_counts failed")
        return []


# --- Login attempt tracking / lockout ---
def record_login_failure(username: str) -> Tuple[bool, int]:
    db = get_db()
    now = datetime.utcnow()
    try:
        row = db.execute(
            "SELECT failure_count, first_failure, lock_until FROM login_attempts WHERE username = ?", (username,)
        ).fetchone()
        if row:
            lock_until = row["lock_until"]
            if lock_until:
                try:
                    lock_until_dt = datetime.fromisoformat(lock_until)
                    if now < lock_until_dt:
                        return False, int((lock_until_dt - now).total_seconds())
                except Exception:
                    pass
            first_failure = (
                datetime.fromisoformat(row["first_failure"]) if row["first_failure"] else now
            )
            if now - first_failure > timedelta(minutes=LOGIN_WINDOW_MINUTES):
                failure_count = 1
                first_failure = now
            else:
                failure_count = (row["failure_count"] or 0) + 1
            lock_until_new = None
            if failure_count >= MAX_FAILURES_BEFORE_LOCK:
                lock_until_new = (now + timedelta(seconds=LOCK_DURATION_SECONDS)).isoformat()
                failure_count = 0
                first_failure = None
            db.execute(
                "REPLACE INTO login_attempts (username, failure_count, first_failure, lock_until) VALUES (?, ?, ?, ?)",
                (
                    username,
                    failure_count,
                    first_failure.isoformat() if first_failure else None,
                    lock_until_new,
                ),
            )
            db.commit()
            if lock_until_new:
                return False, LOCK_DURATION_SECONDS
            return True, failure_count
        else:
            db.execute(
                "INSERT INTO login_attempts (username, failure_count, first_failure, lock_until) VALUES (?, ?, ?, ?)",
                (username, 1, now.isoformat(), None),
            )
            db.commit()
            return True, 1
    except Exception:
        current_app.logger.exception("record_login_failure failed for %s", username)
        return False, 0


def clear_login_attempts(username: str):
    db = get_db()
    try:
        db.execute("DELETE FROM login_attempts WHERE username = ?", (username,))
        db.commit()
    except Exception:
        current_app.logger.exception("clear_login_attempts failed for %s", username)


def is_account_locked_due_to_failures(username: str) -> Tuple[bool, int]:
    db = get_db()
    try:
        row = db.execute("SELECT lock_until FROM login_attempts WHERE username = ?", (username,)).fetchone()
        if not row or not row["lock_until"]:
            return False, 0
        try:
            lock_until_dt = datetime.fromisoformat(row["lock_until"])
        except Exception:
            return False, 0
        now = datetime.utcnow()
        if now < lock_until_dt:
            return True, int((lock_until_dt - now).total_seconds())
        # Lock expired
        db.execute("UPDATE login_attempts SET lock_until=NULL WHERE username = ?", (username,))
        db.commit()
        return False, 0
    except Exception:
        current_app.logger.exception("is_account_locked_due_to_failures failed for %s", username)
        return False, 0


# --- Session token (single-session support) ---
def set_session_token(user_id: int, token: str):
    db = get_db()
    try:
        db.execute("UPDATE users SET session_token=? WHERE id=?", (token, user_id))
        db.commit()
    except Exception:
        current_app.logger.exception("set_session_token failed for %s", user_id)


def get_session_token(user_id: int) -> Optional[str]:
    db = get_db()
    try:
        row = db.execute("SELECT session_token FROM users WHERE id = ?", (user_id,)).fetchone()
        if row:
            return row["session_token"]
    except Exception:
        current_app.logger.exception("get_session_token failed for %s", user_id)
    return None


def clear_session_token(user_id: int):
    db = get_db()
    try:
        db.execute("UPDATE users SET session_token=NULL WHERE id=?", (user_id,))
        db.commit()
    except Exception:
        current_app.logger.exception("clear_session_token failed for %s", user_id)


# --- Housekeeping ---
def purge_old_messages(older_than_seconds: int = MESSAGE_RETENTION_SECONDS):
    db = get_db()
    try:
        cutoff = datetime.utcnow() - timedelta(seconds=older_than_seconds)
        cutoff_iso = cutoff.isoformat() + "Z"
        db.execute("DELETE FROM messages WHERE timestamp < ?", (cutoff_iso,))
        db.commit()
    except Exception:
        current_app.logger.exception("purge_old_messages failed")


def delete_user(user_id: int) -> bool:
    db = get_db()
    try:
        row = db.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            return False
        username = row["username"]
        db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        db.execute("DELETE FROM user_activity WHERE user_id = ?", (user_id,))
        db.execute("DELETE FROM login_attempts WHERE username = ?", (username,))
        db.commit()
        return True
    except Exception:
        current_app.logger.exception("delete_user failed for %s", user_id)
        return False


# --- User object wrapper ---
class User:
    def __init__(self, rowdict: Dict[str, Any]):
        self.id = rowdict["id"]
        self.username = rowdict["username"]
        self.is_admin = bool(rowdict["is_admin"])
        self.is_blocked = bool(rowdict["is_blocked"])
        self.ban_reason = rowdict.get("ban_reason")
        self.strike_count = rowdict.get("strike_count", 0)
        self.session_token = rowdict.get("session_token")

    def get_id(self) -> str:
        return str(self.id)

    @property
    def is_active(self) -> bool:
        return not self.is_blocked

    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def is_anonymous(self) -> bool:
        return False

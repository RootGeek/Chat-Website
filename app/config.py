import os
from pathlib import Path

# Basisverzeichnis dieses Moduls
BASE_DIR = Path(__file__).resolve().parent

# Geheimnis für Sessions / CSRF etc. --> in Produktion unbedingt via ENV setzen!
SECRET_KEY = os.environ.get("SECRET_KEY", "change-me-to-a-secure-random-string")

# Datenbankpfad (kann per ENV überschrieben werden)
DATABASE_PATH = Path(os.environ.get("DATABASE_PATH", BASE_DIR / "instance" / "chat.db"))

# Umgebung / Debugging
FLASK_ENV = os.environ.get("FLASK_ENV", "production")
DEBUG = FLASK_ENV == "development"

# Session/Cookie-Härtung
SESSION_COOKIE_HTTPONLY = True
# SESSION_COOKIE_SECURE sollte in Produktion True sein (nur über HTTPS). Beim lokalen Entwickeln
# wird es automatisch deaktiviert, wenn FLASK_ENV=development gesetzt ist.
SESSION_COOKIE_SECURE = not DEBUG
SESSION_COOKIE_SAMESITE = "Lax"
REMEMBER_COOKIE_SECURE = not DEBUG

# Größenbegrenzung für eingehende Requests, um Missbrauch (z.B. große Payloads) zu begrenzen.
# Da keine Datei-Uploads vorgesehen sind, reicht 1 MiB.
MAX_CONTENT_LENGTH = 1 * 1024 * 1024  # 1 MiB

# Zusätzliche harte Defaults / Sicherheit
PROPAGATE_EXCEPTIONS = False  # nicht unbeabsichtigt Fehler weiterreichen in Produktion

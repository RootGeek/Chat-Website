import os
import logging
from app import create_app

# Umgebung/Debug ableiten
FLASK_ENV = os.environ.get("FLASK_ENV", "production")
debug = FLASK_ENV == "development"

# App + SocketIO erzeugen
app, socketio = create_app()
app.debug = debug  # Konsistent zur Umgebung

# Logging konfigurieren (duplizierte Handler vermeiden)
log_level = logging.DEBUG if app.debug else logging.INFO
if not any(isinstance(h, logging.StreamHandler) for h in app.logger.handlers):
    handler = logging.StreamHandler()
    handler.setLevel(log_level)
    handler.setFormatter(
        logging.Formatter("[%(asctime)s] %(levelname)s in %(module)s: %(message)s")
    )
    app.logger.addHandler(handler)
app.logger.setLevel(log_level)

# Optional: Engine/SocketIO-Logging auf selben Level setzen
logging.getLogger("socketio").setLevel(log_level)
logging.getLogger("engineio").setLevel(log_level)

def main():
    host = os.environ.get("HOST", "127.0.0.1")
    try:
        port = int(os.environ.get("PORT", "5000"))
    except ValueError:
        port = 5000

    # Hinweis: In Produktion sollte TLS & öffentliches Routing über Reverse-Proxy erfolgen.
    try:
        socketio.run(
            app,
            host=host,
            port=port,
            debug=app.debug,
            # allow_unsafe_werkzeug erlaubt das Verwenden des werkzeug-dev-Servers außerhalb von debug,
            # normalerweise nur für Entwicklung; hier nur gesetzt wenn debug ist.
            allow_unsafe_werkzeug=app.debug,
        )
    except Exception:
        app.logger.exception("Fatal error running application")

if __name__ == "__main__":
    # Sicherstellen, dass FLASK_ENV gesetzt ist für Bibliotheken, die darauf schauen
    os.environ.setdefault("FLASK_ENV", "development" if app.debug else "production")
    main()

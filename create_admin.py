from app import create_app
app, socketio = create_app()
with app.app_context():
    from app import models
    success = models.create_user("admin", "Anonymous1997", is_admin=True)
    if success:
        print("Admin-Benutzer 'admin' erstellt.")
    else:
        print("Admin-Benutzer 'admin' existiert bereits.")

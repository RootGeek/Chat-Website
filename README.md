# Chat – End‑User Guide (How to Use This Website)

> **Version:** 1.0 · **Updated:** September 24, 2025  
> This guide explains how to get, install, configure, and run your Chat website locally and in production, without exposing secrets.

---

## 1) What this website is

A lightweight, self‑hosted **web application for real‑time chat** (Flask + optional Socket.IO).  
It’s ideal for small teams, intranets, or personal use.

**Highlights**
- Real‑time messaging (if Socket.IO is enabled)
- Session‑based authentication (if included in your build)
- Safe session handling with a **persistent `SECRET_KEY`** (auto‑created in Dev)
- Simple setup; runs on Windows, Linux, macOS

**Not included by default**
- Media uploads/transcoding, multi‑tenant support, or E2E encryption
- Massive permissions matrix (unless you add it)
- Push notifications

---

## 2) System Requirements

- **Python 3.10+**
- Git (optional; recommended)
- OS: Windows 10/11, Ubuntu/Debian, macOS 12+
- (Production) Nginx, Gunicorn, gevent or eventlet; optional Redis for scaling

---

## 3) Get the Code

### Option A — Download ZIP (easiest)
1. Go to your GitHub repo → **Code** → **Download ZIP**.
2. Extract it, e.g. to: `C:\Users\<you>\Downloads\Chat` (Windows) or `~/Downloads/Chat` (Linux/macOS).

### Option B — Clone via Git
```bash
git clone <YOUR_REPO_URL>
cd Chat
```

> If the repo is private, you’ll need access rights or a personal access token.

---

## 4) Development Setup (local)

### Windows (PowerShell)
```powershell
cd Chat
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
python run.py
```
Open the URL printed in the console (usually **http://127.0.0.1:5000**).

### Linux/macOS (bash)
```bash
cd Chat
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python run.py
```
Open the URL printed in the console (usually **http://127.0.0.1:5000**).

**Notes**
- On first run in Dev, a secure `SECRET_KEY` is auto‑created under `instance/SECRET_KEY`.  
- Make sure the process can **write** to `instance/`.
- Stop with **Ctrl+C**.

---

## 5) Configuration (Environment Variables)

While Dev works out‑of‑the‑box, you can tweak behavior via ENV vars:

| Variable | Purpose | Recommended (Prod) |
|---|---|---|
| `FLASK_ENV` | `development` or `production` | `production` |
| `SECRET_KEY` | Cryptographic secret for sessions/CSRF | Long, random string |
| `PREFERRED_URL_SCHEME` | URL scheme | `https` |
| `SESSION_COOKIE_SECURE` | Only send cookie via HTTPS | `True` |
| `REMEMBER_COOKIE_SECURE` | Same as above for remember‑me | `True` |
| `SOCKETIO_MESSAGE_QUEUE` | Redis URL for multi‑worker scaling | `redis://localhost:6379/0` |

**Dev**: You **don’t** need to set `SECRET_KEY` manually.  
**Prod**: You **must** set `SECRET_KEY` or provide the file `instance/SECRET_KEY`.

Create a strong key:
```bash
python - <<'PY'
import secrets; print(secrets.token_urlsafe(64))
PY
```

---

## 6) Running in Production (quick path)

> This section assumes Ubuntu/Debian, but works similarly elsewhere.

### 6.1 Prepare
```bash
sudo apt update
sudo apt install -y python3-venv python3-pip nginx
cd /var/www
sudo mkdir Chat && sudo chown $USER:$USER Chat
cd Chat
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 6.2 Set environment
```bash
export FLASK_ENV=production
export SECRET_KEY="$(python - <<'PY'\nimport secrets; print(secrets.token_urlsafe(64))\nPY)"
export PREFERRED_URL_SCHEME=https
```

### 6.3 Start with Gunicorn
```bash
pip install gunicorn gevent
gunicorn -w 2 -k gevent -b 127.0.0.1:8000 "app:create_app()"
```
Keep this running (or use a systemd service as below).

### 6.4 Nginx reverse proxy (TLS)
**/etc/nginx/sites-available/chat.conf**
```nginx
server {
    listen 80;
    server_name chat.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name chat.example.com;

    ssl_certificate     /etc/letsencrypt/live/chat.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/chat.example.com/privkey.pem;

    client_max_body_size 10m;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;

        # WebSocket upgrade for Socket.IO
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```
Enable & reload:
```bash
sudo ln -s /etc/nginx/sites-available/chat.conf /etc/nginx/sites-enabled/chat.conf
sudo nginx -t && sudo systemctl reload nginx
```

### 6.5 Optional: systemd service
**/etc/systemd/system/chat.service**
```ini
[Unit]
Description=Chat (Flask) – Gunicorn
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/var/www/Chat
Environment="FLASK_ENV=production"
Environment="SECRET_KEY=***long_secure_random_string***"
Environment="PREFERRED_URL_SCHEME=https"
ExecStart=/var/www/Chat/.venv/bin/gunicorn -w 2 -k gevent -b 127.0.0.1:8000 "app:create_app()"
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```
```bash
sudo systemctl daemon-reload
sudo systemctl enable chat
sudo systemctl start chat
```

---

## 7) Using the Website

- **Open** the URL shown by the server (Dev: usually `http://127.0.0.1:5000`; Prod: your domain).
- **Login/Signup**: If your build includes auth, use the provided credentials or create an account per your admin’s process.
- **Chat**:
  - Join the default room or select a room (if supported).
  - Type your message and send; other users connected will see it in real time.
- **Refresh/Reconnect**: If the page becomes unresponsive, refresh the browser; Socket.IO will auto‑reconnect if configured.

> Exact UI labels and routes can vary slightly depending on your branch/template.

---

## 8) Privacy & Security

- The app does **not** ship with any secret keys in the repo.  
- In Dev, a `SECRET_KEY` file is auto‑generated and stored **locally** under `instance/SECRET_KEY`. Do **not** commit it.  
- Use HTTPS in production, set `SESSION_COOKIE_SECURE=True`, `REMEMBER_COOKIE_SECURE=True`.  
- Never paste tokens/passwords into logs or commit history.  
- Back up `instance/SECRET_KEY` and your database (if used).

---

## 9) Troubleshooting

**Can’t start: `RuntimeError: SECRET_KEY must be set...`**  
- You’re likely running an older build or in Prod without a key.  
- Dev: ensure the process can write to `instance/`.  
- Prod: set `SECRET_KEY` env var or place `instance/SECRET_KEY` file with your key.

**CSRF errors on forms**  
- Reload the page and try again.  
- Ensure `SECRET_KEY` is stable (not changing every boot).  
- Templates must include `{{ form.csrf_token }}` if using Flask‑WTF.

**WebSocket not connecting behind Nginx**  
- Ensure upgrade headers are present (see Nginx snippet).  
- Check firewall/port; for multiple workers, set `SOCKETIO_MESSAGE_QUEUE` (Redis).

**Permission errors writing to `instance/`**  
- Create the folder and ensure ownership/permissions allow the app to write.

---

## 10) Updating the App

```bash
git pull                # or download a fresh ZIP
source .venv/bin/activate
pip install -r requirements.txt
# restart dev server or systemd service
```

If your update changes dependencies or database models, follow the release notes/migration steps (if any).

---

## 11) Uninstall / Cleanup

- Stop the server (Ctrl+C or `systemctl stop chat`).  
- Remove the project folder and virtual environment.  
- Remove the systemd unit and Nginx site if you set them up.  
- Optional: delete the database and `instance/SECRET_KEY` if you no longer need them.

---

## 12) FAQ

- **Do I need Docker?** No. It runs fine without it.  
- **Is Redis required?** Only for multi‑worker scaling or multiple app instances.  
- **Where do I change app settings?** Prefer **environment variables**; `config.py` holds defaults.  
- **Can I use a different port?** Yes—adjust the Gunicorn bind (`-b 127.0.0.1:PORT`) or your `run.py`.

---

## 13) Support / Contact

- Report issues in your GitHub repo’s **Issues** tab.  
- For help with deployment, share your OS, Python version, error logs, and steps you tried.

---

## 14) License

- See `LICENSE` in the repository (e.g., MIT), or add one if missing.

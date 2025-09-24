import random
import time
import io
from urllib.parse import urlparse, urljoin
from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    current_app,
    send_file,
)
from flask_login import login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFError

from . import models
from .models import User
import secrets
from PIL import Image, ImageDraw, ImageFont

bp = Blueprint("auth", __name__, url_prefix="/auth")

USERNAME_MAX_LENGTH = 150
PASSWORD_MIN_LENGTH = 8
LOGIN_FAILURE_DELAY_SECONDS = 0.25


def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ("http", "https") and ref_url.netloc == test_url.netloc


def _generate_captcha_text():
    a = random.randint(1, 9)
    b = random.randint(1, 9)
    answer = a + b
    session["captcha_answer"] = str(answer)
    try:
        current_app.logger.debug(f"[Captcha-text] generated {a}+{b}, expected={answer}")
    except Exception:
        pass
    return f"{a} + {b} = ?"


@bp.route("/captcha_image")
def captcha_image():
    try:
        a = random.randint(1, 9)
        b = random.randint(1, 9)
        answer = a + b
        session["captcha_answer"] = str(answer)
        current_app.logger.debug(f"[Captcha-image] generated {a}+{b}, expected={answer}")

        width, height = 150, 50
        img = Image.new("RGB", (width, height), (15, 17, 26))
        draw = ImageDraw.Draw(img)

        try:
            font = ImageFont.truetype("DejaVuSansMono.ttf", 24)
        except Exception:
            font = ImageFont.load_default()

        text = f"{a} + {b} = ?"
        bbox = draw.textbbox((0, 0), text, font=font)
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]
        x = (width - text_width) // 2
        y = (height - text_height) // 2
        draw.text((x, y), text, font=font, fill=(0, 255, 127))

        for _ in range(100):
            nx = random.randint(0, width - 1)
            ny = random.randint(0, height - 1)
            draw.point((nx, ny), fill=(60, 60, 60))

        for _ in range(2):
            x1 = random.randint(0, width)
            y1 = random.randint(0, height)
            x2 = random.randint(0, width)
            y2 = random.randint(0, height)
            draw.line((x1, y1, x2, y2), fill=(30, 30, 30))

        buf = io.BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)
        response = send_file(buf, mimetype="image/png")
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response

    except Exception:
        current_app.logger.exception("Captcha image generation failed, falling back to SVG")

        a = random.randint(1, 9)
        b = random.randint(1, 9)
        session["captcha_answer"] = str(a + b)
        svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="150" height="50">
  <rect width="100%" height="100%" fill="#0f111a"/>
  <text x="50%" y="50%" dominant-baseline="middle" text-anchor="middle" font-family="monospace" font-size="20" fill="#00ff7f">{a} + {b} = ?</text>
</svg>"""
        resp = current_app.response_class(svg, mimetype="image/svg+xml")
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        return resp


@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("chat.chatroom"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        captcha_resp = request.form.get("captcha", "").strip()

        expected = session.get("captcha_answer")
        current_app.logger.debug(
            f"[Login attempt] user={username} provided_captcha='{captcha_resp}' expected='{expected}'"
        )

        if not expected or not captcha_resp.isdigit() or int(captcha_resp) != int(expected):
            flash("Captcha incorrect.", "error")
            captcha_question = _generate_captcha_text()
            return render_template("login.html", captcha_question=captcha_question)

        session.pop("captcha_answer", None)

        locked, remaining = models.is_account_locked_due_to_failures(username)
        if locked:
            flash(f"Account temporarily locked. Try again in {remaining} seconds.", "error")
            captcha_question = _generate_captcha_text()
            return render_template("login.html", captcha_question=captcha_question)

        user_dict, reason = models.verify_user(username, password)
        if user_dict is None:
            if reason != "blocked":
                time.sleep(LOGIN_FAILURE_DELAY_SECONDS)
                success, val = models.record_login_failure(username)
                if not success and val:
                    flash(f"Account locked due to failures. Try again in {val} seconds.", "error")
                else:
                    flash("Username or password incorrect.", "error")
            else:
                return redirect(url_for("auth.banned"))
            captcha_question = _generate_captcha_text()
            return render_template("login.html", captcha_question=captcha_question)

        models.clear_login_attempts(username)
        user_obj = User(user_dict)
        session.clear()
        login_user(user_obj)

        next_page = request.args.get("next")
        if next_page and is_safe_url(next_page):
            return redirect(next_page)
        return redirect(url_for("chat.chatroom"))

    captcha_question = _generate_captcha_text()
    return render_template("login.html", captcha_question=captcha_question)


@bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("chat.chatroom"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        password2 = request.form.get("password2", "")
        captcha_resp = request.form.get("captcha", "").strip()

        expected = session.get("captcha_answer")
        current_app.logger.debug(
            f"[Register attempt] user={username} provided_captcha='{captcha_resp}' expected='{expected}'"
        )

        if not expected or not captcha_resp.isdigit() or int(captcha_resp) != int(expected):
            flash("Captcha incorrect.", "error")
            captcha_question = _generate_captcha_text()
            return render_template("register.html", captcha_question=captcha_question)

        if password != password2:
            flash("Passwords do not match.", "error")
            captcha_question = _generate_captcha_text()
            return render_template("register.html", captcha_question=captcha_question)

        if not username or not password:
            flash("Username and password required.", "error")
            captcha_question = _generate_captcha_text()
            return render_template("register.html", captcha_question=captcha_question)

        if len(username) > USERNAME_MAX_LENGTH:
            flash(f"Username too long (max {USERNAME_MAX_LENGTH} characters).", "error")
            captcha_question = _generate_captcha_text()
            return render_template("register.html", captcha_question=captcha_question)

        if len(password) < PASSWORD_MIN_LENGTH:
            flash(f"Password must be at least {PASSWORD_MIN_LENGTH} characters.", "error")
            captcha_question = _generate_captcha_text()
            return render_template("register.html", captcha_question=captcha_question)

        success = models.create_user(username, password)
        if not success:
            flash("Username already exists.", "error")
            captcha_question = _generate_captcha_text()
            return render_template("register.html", captcha_question=captcha_question)

        flash("Account created. Please log in.", "success")
        return redirect(url_for("auth.login"))

    captcha_question = _generate_captcha_text()
    return render_template("register.html", captcha_question=captcha_question)


@bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.", "success")
    return redirect(url_for("auth.login"))


@bp.route("/banned")
def banned():
    reason = request.args.get("reason")
    if reason and isinstance(reason, str) and reason.lower() == "none":
        reason = None

    user_id = request.args.get("user_id", type=int)
    if not reason and user_id:
        user_obj = models.get_user_by_id(user_id)
        if user_obj and getattr(user_obj, "is_blocked", False):
            reason = user_obj.ban_reason

    if current_user.is_authenticated:
        logout_user()
    return render_template("banned.html", reason=reason)

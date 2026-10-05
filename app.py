import os
import re
import secrets
import smtplib
from datetime import datetime, timedelta
from email.message import EmailMessage

from flask import Flask, flash, redirect, render_template, request, url_for
from flask_login import (LoginManager, UserMixin, current_user, login_required,
                         login_user, logout_user)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),  # set in production!
    SQLALCHEMY_DATABASE_URI="sqlite:///users.db",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") == "production",  # HTTPS only in prod
    REMEMBER_COOKIE_HTTPONLY=True,
)

db = SQLAlchemy(app)
csrf = CSRFProtect(app)  # CSRF token required on every POST form
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "info"
serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="email-verify")

TOKEN_MAX_AGE = 60 * 60 * 24   # verification link valid for 24 hours
MAX_ATTEMPTS = 5               # failed logins before temporary lock
LOCK_MINUTES = 15
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    phone = db.Column(db.String(20))
    password_hash = db.Column(db.String(255), nullable=False)
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    failed_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# ---------- helpers ----------
def password_problems(pw):
    problems = []
    if len(pw) < 8:
        problems.append("at least 8 characters")
    if not re.search(r"[a-z]", pw):
        problems.append("a lowercase letter")
    if not re.search(r"[A-Z]", pw):
        problems.append("an uppercase letter")
    if not re.search(r"\d", pw):
        problems.append("a number")
    return problems


def send_verification_email(user):
    token = serializer.dumps(user.email)
    link = url_for("verify_email", token=token, _external=True)
    server = os.environ.get("MAIL_SERVER")
    if not server:  # dev mode: no SMTP configured
        print(f"\n[DEV] Verification link for {user.email}:\n{link}\n")
        return
    msg = EmailMessage()
    msg["Subject"] = "Verify your email address"
    msg["From"] = os.environ.get("MAIL_SENDER", os.environ.get("MAIL_USERNAME"))
    msg["To"] = user.email
    msg.set_content(
        f"Hi {user.full_name},\n\nConfirm your email to activate your account:\n{link}\n\n"
        "This link expires in 24 hours. If you didn't sign up, ignore this email."
    )
    with smtplib.SMTP(server, int(os.environ.get("MAIL_PORT", 587))) as smtp:
        smtp.starttls()
        smtp.login(os.environ["MAIL_USERNAME"], os.environ["MAIL_PASSWORD"])
        smtp.send_message(msg)


# ---------- routes ----------
@app.route("/")
def index():
    return redirect(url_for("dashboard" if current_user.is_authenticated else "login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    form = {}
    if request.method == "POST":
        form = {k: request.form.get(k, "").strip() for k in ("full_name", "email", "phone")}
        form["email"] = form["email"].lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        errors = []
        if not form["full_name"]:
            errors.append("Enter your full name.")
        if not EMAIL_RE.match(form["email"]):
            errors.append("Enter a valid email address.")
        if form["phone"] and not re.fullmatch(r"\+?[\d\s\-]{7,15}", form["phone"]):
            errors.append("Enter a valid phone number, or leave it blank.")
        if password_problems(password):
            errors.append("Password needs " + ", ".join(password_problems(password)) + ".")
        if password != confirm:
            errors.append("Passwords don't match.")
        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("register.html", form=form)

        existing = User.query.filter_by(email=form["email"]).first()
        if existing is None:
            user = User(full_name=form["full_name"], email=form["email"], phone=form["phone"],
                        password_hash=generate_password_hash(password))
            db.session.add(user)
            db.session.commit()
            send_verification_email(user)
        # Same response whether or not the email exists (prevents account enumeration)
        flash("Check your inbox. We sent a verification link to finish creating your account.", "success")
        return redirect(url_for("login"))
    return render_template("register.html", form=form)


@app.route("/verify/<token>")
def verify_email(token):
    try:
        email = serializer.loads(token, max_age=TOKEN_MAX_AGE)
    except SignatureExpired:
        flash("That link has expired. Request a new one below.", "error")
        return redirect(url_for("resend"))
    except BadSignature:
        flash("That verification link isn't valid.", "error")
        return redirect(url_for("login"))
    user = User.query.filter_by(email=email).first_or_404()
    if not user.is_verified:
        user.is_verified = True
        db.session.commit()
    flash("Email verified. You can log in now.", "success")
    return redirect(url_for("login"))


@app.route("/resend", methods=["GET", "POST"])
def resend():
    if request.method == "POST":
        user = User.query.filter_by(email=request.form.get("email", "").strip().lower()).first()
        if user and not user.is_verified:
            send_verification_email(user)
        flash("If that email has an unverified account, a new link is on its way.", "success")
        return redirect(url_for("login"))
    return render_template("resend.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()

        if user and user.locked_until and user.locked_until > datetime.utcnow():
            flash("Too many failed attempts. Try again in a few minutes.", "error")
            return render_template("login.html", email=email)

        if user and check_password_hash(user.password_hash, password):
            if not user.is_verified:
                flash("Verify your email before logging in.", "error")
                return render_template("login.html", email=email, unverified=True)
            user.failed_attempts, user.locked_until = 0, None
            db.session.commit()
            login_user(user, remember=bool(request.form.get("remember")))
            return redirect(url_for("dashboard"))

        if user:
            user.failed_attempts += 1
            if user.failed_attempts >= MAX_ATTEMPTS:
                user.locked_until = datetime.utcnow() + timedelta(minutes=LOCK_MINUTES)
                user.failed_attempts = 0
            db.session.commit()
        flash("Incorrect email or password.", "error")  # never reveal which one was wrong
        return render_template("login.html", email=email)
    return render_template("login.html", email="")


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("You're logged out.", "success")
    return redirect(url_for("login"))


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'"
    return resp


with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)
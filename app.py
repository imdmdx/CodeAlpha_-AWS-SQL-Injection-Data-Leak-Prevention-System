import os
import re
import logging

from datetime import datetime, timezone, timedelta

from dotenv import load_dotenv

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    jsonify
)

from flask_wtf import CSRFProtect

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from sqlalchemy.exc import IntegrityError

from models import db, User, Capability

from security import (
    hash_password,
    verify_password,
    encrypt_sensitive_data,
    decrypt_sensitive_data,
    generate_capability_code,
    hash_capability_code
)


# =========================================================
# ENVIRONMENT
# =========================================================

load_dotenv()


# =========================================================
# FLASK APPLICATION
# =========================================================

app = Flask(__name__)


SECRET_KEY = os.getenv("SECRET_KEY")

if not SECRET_KEY:
    raise RuntimeError(
        "SECRET_KEY is not configured."
    )


app.config["SECRET_KEY"] = SECRET_KEY


# =========================================================
# DATABASE
# =========================================================

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    # Local testing fallback.
    # For AWS deployment, configure DATABASE_URL
    # to point to your RDS MySQL database.
    DATABASE_URL = "sqlite:///security_project.db"


app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False


# =========================================================
# SECURITY CONFIGURATION
# =========================================================

app.config["SESSION_COOKIE_HTTPONLY"] = True

app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Set this to True when the production application
# is running entirely over HTTPS.
app.config["SESSION_COOKIE_SECURE"] = (
    os.getenv("SESSION_COOKIE_SECURE", "False").lower()
    == "true"
)


# =========================================================
# INITIALIZE EXTENSIONS
# =========================================================

db.init_app(app)

csrf = CSRFProtect(app)


limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[
        "200 per day",
        "50 per hour"
    ],
    storage_uri="memory://"
)


# =========================================================
# LOGGING
# =========================================================

logging.basicConfig(
    level=logging.INFO,
    format=(
        "%(asctime)s - "
        "%(levelname)s - "
        "%(message)s"
    ),
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


# =========================================================
# INPUT VALIDATION
# =========================================================

USERNAME_PATTERN = re.compile(
    r"^[A-Za-z0-9_]{3,30}$"
)


EMAIL_PATTERN = re.compile(
    r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
)


def validate_registration(
    username,
    email,
    password,
    phone
):

    errors = []

    username = username.strip()

    email = email.strip().lower()

    phone = phone.strip()

    if not USERNAME_PATTERN.fullmatch(username):
        errors.append(
            "Username must contain 3-30 letters, "
            "numbers, or underscores."
        )

    if not EMAIL_PATTERN.fullmatch(email):
        errors.append(
            "Please enter a valid email address."
        )

    if len(password) < 8:
        errors.append(
            "Password must contain at least 8 characters."
        )

    if phone and not re.fullmatch(
        r"[0-9+\-\s]{7,20}",
        phone
    ):
        errors.append(
            "Invalid phone number format."
        )

    return errors


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():

    if "user_id" in session:
        return redirect(
            url_for("dashboard")
        )

    return redirect(
        url_for("login")
    )


# =========================================================
# REGISTER
# =========================================================

@app.route(
    "/register",
    methods=["GET", "POST"]
)
@limiter.limit("10 per hour")
def register():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        )

        email = request.form.get(
            "email",
            ""
        )

        password = request.form.get(
            "password",
            ""
        )

        phone = request.form.get(
            "phone",
            ""
        )

        errors = validate_registration(
            username,
            email,
            password,
            phone
        )

        if errors:

            for error in errors:
                flash(error, "danger")

            return render_template(
                "register.html"
            )

        username = username.strip()

        email = email.strip().lower()

        phone = phone.strip()

        # Check existing user.
        # SQLAlchemy generates a parameterized query.
        existing_user = User.query.filter(
            (
                (User.username == username)
                |
                (User.email == email)
            )
        ).first()

        if existing_user:

            flash(
                "Username or email already exists.",
                "danger"
            )

            return render_template(
                "register.html"
            )

        password_hash = hash_password(
            password
        )

        encrypted_phone = None

        if phone:

            encrypted_phone = encrypt_sensitive_data(
                phone
            )

        user = User(
            username=username,
            email=email,
            password_hash=password_hash,
            phone_encrypted=encrypted_phone
        )

        try:

            db.session.add(user)

            db.session.commit()

        except IntegrityError:

            db.session.rollback()

            flash(
                "Username or email already exists.",
                "danger"
            )

            return render_template(
                "register.html"
            )

        logger.info(
            "New user registered: user_id=%s",
            user.id
        )

        flash(
            "Registration successful. Please log in.",
            "success"
        )

        return redirect(
            url_for("login")
        )

    return render_template(
        "register.html"
    )


# =========================================================
# LOGIN
# =========================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
@limiter.limit("5 per minute")
def login():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        if not username or not password:

            flash(
                "Username and password are required.",
                "danger"
            )

            return render_template(
                "login.html"
            )

        # SQLAlchemy parameterized query.
        user = User.query.filter_by(
            username=username
        ).first()

        if not user:

            logger.warning(
                "Failed login attempt"
            )

            flash(
                "Invalid username or password.",
                "danger"
            )

            return render_template(
                "login.html"
            )

        if not verify_password(
            user.password_hash,
            password
        ):

            logger.warning(
                "Failed login attempt for user_id=%s",
                user.id
            )

            flash(
                "Invalid username or password.",
                "danger"
            )

            return render_template(
                "login.html"
            )

        # Clear any previous session.
        session.clear()

        session["user_id"] = user.id

        session["username"] = user.username

        logger.info(
            "Successful login: user_id=%s",
            user.id
        )

        flash(
            "Login successful.",
            "success"
        )

        return redirect(
            url_for("dashboard")
        )

    return render_template(
        "login.html"
    )


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    user_id = session.get(
        "user_id"
    )

    session.clear()

    logger.info(
        "User logged out: user_id=%s",
        user_id
    )

    flash(
        "You have been logged out.",
        "success"
    )

    return redirect(
        url_for("login")
    )


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:

        flash(
            "Please log in first.",
            "danger"
        )

        return redirect(
            url_for("login")
        )

    user = db.session.get(
        User,
        session["user_id"]
    )

    if not user:

        session.clear()

        flash(
            "User account was not found.",
            "danger"
        )

        return redirect(
            url_for("login")
        )

    phone = None

    if user.phone_encrypted:

        try:

            phone = decrypt_sensitive_data(
                user.phone_encrypted
            )

        except Exception:

            logger.exception(
                "Unable to decrypt sensitive data"
            )

            phone = "Unable to decrypt"

    return render_template(
        "dashboard.html",
        user=user,
        phone=phone
    )


# =========================================================
# GENERATE CAPABILITY CODE
# =========================================================

@app.route(
    "/generate-capability",
    methods=["POST"]
)
@limiter.limit("5 per minute")
def generate_capability():

    if "user_id" not in session:

        return jsonify({
            "success": False,
            "message": "Authentication required."
        }), 401

    user_id = session["user_id"]

    capability_code = generate_capability_code()

    code_hash = hash_capability_code(
        capability_code
    )

    expires_at = (
        datetime.now(timezone.utc)
        + timedelta(minutes=15)
    )

    capability = Capability(
        user_id=user_id,
        code_hash=code_hash,
        scope="view_profile",
        expires_at=expires_at,
        used=False
    )

    db.session.add(capability)

    db.session.commit()

    logger.info(
        "Capability generated: user_id=%s capability_id=%s",
        user_id,
        capability.id
    )

    return jsonify({
        "success": True,
        "message": (
            "Capability generated. "
            "It expires in 15 minutes."
        ),
        "capability_code": capability_code
    })


# =========================================================
# PROTECTED PROFILE API
# =========================================================

@app.route(
    "/api/secure-profile",
    methods=["GET"]
)
@limiter.limit("20 per minute")
def secure_profile():

    if "user_id" not in session:

        return jsonify({
            "success": False,
            "message": "Authentication required."
        }), 401

    capability_code = request.headers.get(
        "X-Capability-Code",
        ""
    ).strip()

    if not capability_code:

        return jsonify({
            "success": False,
            "message": "Capability code required."
        }), 403

    code_hash = hash_capability_code(
        capability_code
    )

    capability = Capability.query.filter_by(
        code_hash=code_hash,
        user_id=session["user_id"],
        scope="view_profile",
        used=False
    ).first()

    if not capability:

        logger.warning(
            "Invalid capability attempt: user_id=%s",
            session["user_id"]
        )

        return jsonify({
            "success": False,
            "message": "Invalid capability code."
        }), 403

    now = datetime.now(timezone.utc)

    # Some database configurations may return
    # a timezone-naive datetime.
    expires_at = capability.expires_at

    if expires_at.tzinfo is None:

        expires_at = expires_at.replace(
            tzinfo=timezone.utc
        )

    if expires_at < now:

        logger.warning(
            "Expired capability attempt: user_id=%s",
            session["user_id"]
        )

        return jsonify({
            "success": False,
            "message": "Capability code has expired."
        }), 403

    user = db.session.get(
        User,
        session["user_id"]
    )

    if not user:

        return jsonify({
            "success": False,
            "message": "User not found."
        }), 404

    phone = None

    if user.phone_encrypted:

        phone = decrypt_sensitive_data(
            user.phone_encrypted
        )

    # Make capability one-time-use.
    capability.used = True

    db.session.commit()

    logger.info(
        "Protected profile accessed: user_id=%s",
        user.id
    )

    return jsonify({
        "success": True,
        "data": {
            "username": user.username,
            "email": user.email,
            "phone": phone,
            "created_at": user.created_at.isoformat()
        }
    })


# =========================================================
# ERROR HANDLERS
# =========================================================

@app.errorhandler(404)
def not_found(error):

    return render_template(
        "login.html"
    ), 404


@app.errorhandler(429)
def rate_limit_error(error):

    return jsonify({
        "success": False,
        "message": "Too many requests. Try again later."
    }), 429


@app.errorhandler(500)
def server_error(error):

    logger.exception(
        "Internal server error"
    )

    return jsonify({
        "success": False,
        "message": "Internal server error."
    }), 500


# =========================================================
# DATABASE INITIALIZATION
# =========================================================

with app.app_context():

    db.create_all()


# =========================================================
# APPLICATION START
# =========================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )

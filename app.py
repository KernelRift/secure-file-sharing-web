import os
import sqlite3
import secrets
from datetime import datetime, timedelta

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    send_file,
    abort,
    flash
)

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from cryptography.fernet import Fernet


app = Flask(__name__)

app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "change-this-development-secret"
)

DATABASE = "files.db"
UPLOAD_FOLDER = "encrypted_files"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# --------------------------------------------------
# Encryption key
# --------------------------------------------------

KEY_FILE = "encryption.key"


def load_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as file:
            return file.read()

    key = Fernet.generate_key()

    with open(KEY_FILE, "wb") as file:
        file.write(key)

    return key


ENCRYPTION_KEY = load_or_create_key()
cipher = Fernet(ENCRYPTION_KEY)


# --------------------------------------------------
# Database
# --------------------------------------------------

def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():

    db = get_db()

    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            stored_filename TEXT NOT NULL,
            owner_id INTEGER NOT NULL,
            uploaded_at TEXT NOT NULL,
            FOREIGN KEY(owner_id) REFERENCES users(id)
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS download_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT UNIQUE NOT NULL,
            file_id INTEGER NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY(file_id) REFERENCES files(id)
        )
    """)

    db.commit()
    db.close()


# --------------------------------------------------
# Authentication helpers
# --------------------------------------------------

def current_user():

    if "user_id" not in session:
        return None

    db = get_db()

    user = db.execute(
        "SELECT * FROM users WHERE id = ?",
        (session["user_id"],)
    ).fetchone()

    db.close()

    return user


def login_required():

    if "user_id" not in session:
        return False

    return True


# --------------------------------------------------
# Register
# --------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"].strip()
        password = request.form["password"]

        if len(username) < 3:
            flash("Username must contain at least 3 characters.")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Password must contain at least 8 characters.")
            return redirect(url_for("register"))

        password_hash = generate_password_hash(password)

        db = get_db()

        try:

            db.execute(
                """
                INSERT INTO users (username, password, role)
                VALUES (?, ?, ?)
                """,
                (username, password_hash, "user")
            )

            db.commit()

        except sqlite3.IntegrityError:

            flash("Username already exists.")
            db.close()

            return redirect(url_for("register"))

        db.close()

        flash("Registration successful. Please login.")

        return redirect(url_for("login"))

    return render_template("register.html")


# --------------------------------------------------
# Login
# --------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        db = get_db()

        user = db.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        db.close()

        if user and check_password_hash(
            user["password"],
            password
        ):

            session.clear()

            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]

            return redirect(url_for("dashboard"))

        flash("Invalid username or password.")

    return render_template("login.html")


# --------------------------------------------------
# Logout
# --------------------------------------------------

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))


# --------------------------------------------------
# Dashboard
# --------------------------------------------------

@app.route("/")
def dashboard():

    if not login_required():
        return redirect(url_for("login"))

    db = get_db()

    files = db.execute(
        """
        SELECT files.*, users.username
        FROM files
        JOIN users ON files.owner_id = users.id
        ORDER BY files.id DESC
        """
    ).fetchall()

    db.close()

    return render_template(
        "dashboard.html",
        files=files,
        user=current_user()
    )


# --------------------------------------------------
# Upload
# --------------------------------------------------

@app.route("/upload", methods=["GET", "POST"])
def upload():

    if not login_required():
        return redirect(url_for("login"))

    if request.method == "POST":

        uploaded_file = request.files.get("file")

        if not uploaded_file or uploaded_file.filename == "":
            flash("Please select a file.")
            return redirect(url_for("upload"))

        original_filename = secure_filename(
            uploaded_file.filename
        )

        if not original_filename:
            flash("Invalid filename.")
            return redirect(url_for("upload"))

        file_data = uploaded_file.read()

        encrypted_data = cipher.encrypt(file_data)

        stored_filename = secrets.token_hex(32) + ".enc"

        encrypted_path = os.path.join(
            UPLOAD_FOLDER,
            stored_filename
        )

        with open(encrypted_path, "wb") as encrypted_file:
            encrypted_file.write(encrypted_data)

        db = get_db()

        db.execute(
            """
            INSERT INTO files
            (filename, stored_filename, owner_id, uploaded_at)
            VALUES (?, ?, ?, ?)
            """,
            (
                original_filename,
                stored_filename,
                session["user_id"],
                datetime.utcnow().isoformat()
            )
        )

        db.commit()
        db.close()

        flash("File uploaded and encrypted successfully.")

        return redirect(url_for("dashboard"))

    return render_template("upload.html")


# --------------------------------------------------
# Download
# --------------------------------------------------

@app.route("/download/<int:file_id>")
def download(file_id):

    if not login_required():
        return redirect(url_for("login"))

    db = get_db()

    file_record = db.execute(
        "SELECT * FROM files WHERE id = ?",
        (file_id,)
    ).fetchone()

    db.close()

    if not file_record:
        abort(404)

    # RBAC / ownership check
    if (
        file_record["owner_id"] != session["user_id"]
        and session.get("role") != "admin"
    ):
        abort(403)

    encrypted_path = os.path.join(
        UPLOAD_FOLDER,
        file_record["stored_filename"]
    )

    if not os.path.exists(encrypted_path):
        abort(404)

    with open(encrypted_path, "rb") as encrypted_file:
        encrypted_data = encrypted_file.read()

    try:
        decrypted_data = cipher.decrypt(encrypted_data)

    except Exception:
        abort(500)

    temporary_file = os.path.join(
        UPLOAD_FOLDER,
        "tmp_" + secrets.token_hex(16)
    )

    with open(temporary_file, "wb") as file:
        file.write(decrypted_data)

    return send_file(
        temporary_file,
        as_attachment=True,
        download_name=file_record["filename"]
    )


# --------------------------------------------------
# Generate temporary download link
# --------------------------------------------------

@app.route("/share/<int:file_id>")
def create_share_link(file_id):

    if not login_required():
        return redirect(url_for("login"))

    db = get_db()

    file_record = db.execute(
        "SELECT * FROM files WHERE id = ?",
        (file_id,)
    ).fetchone()

    if not file_record:
        db.close()
        abort(404)

    if file_record["owner_id"] != session["user_id"]:
        db.close()
        abort(403)

    token = secrets.token_urlsafe(32)

    expiration = datetime.utcnow() + timedelta(minutes=10)

    db.execute(
        """
        INSERT INTO download_tokens
        (token, file_id, expires_at)
        VALUES (?, ?, ?)
        """,
        (
            token,
            file_id,
            expiration.isoformat()
        )
    )

    db.commit()
    db.close()

    return render_template(
        "dashboard.html",
        files=[file_record],
        user=current_user(),
        share_link=url_for(
            "temporary_download",
            token=token,
            _external=True
        ),
        expiration=expiration
    )


# --------------------------------------------------
# Temporary download
# --------------------------------------------------

@app.route("/temporary/<token>")
def temporary_download(token):

    db = get_db()

    token_record = db.execute(
        """
        SELECT download_tokens.*, files.*
        FROM download_tokens
        JOIN files
        ON download_tokens.file_id = files.id
        WHERE download_tokens.token = ?
        """,
        (token,)
    ).fetchone()

    db.close()

    if not token_record:
        abort(404)

    expiration = datetime.fromisoformat(
        token_record["expires_at"]
    )

    if datetime.utcnow() > expiration:
        abort(403, description="Download link has expired.")

    encrypted_path = os.path.join(
        UPLOAD_FOLDER,
        token_record["stored_filename"]
    )

    if not os.path.exists(encrypted_path):
        abort(404)

    with open(encrypted_path, "rb") as encrypted_file:
        encrypted_data = encrypted_file.read()

    decrypted_data = cipher.decrypt(encrypted_data)

    temporary_file = os.path.join(
        UPLOAD_FOLDER,
        "shared_" + secrets.token_hex(16)
    )

    with open(temporary_file, "wb") as file:
        file.write(decrypted_data)

    return send_file(
        temporary_file,
        as_attachment=True,
        download_name=token_record["filename"]
    )


# --------------------------------------------------
# Application startup
# --------------------------------------------------

initialize_database()


if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )

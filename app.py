from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
import random, os
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, set_access_cookies, unset_jwt_cookies, get_jwt
)
from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

from config import Config
from db import init_db, get_db_connection
from google_auth_oauthlib.flow import Flow
import json
from datetime import timedelta
import os


# Google OAuth setup
client_config = {
    "web": {
        "client_id": Config.GOOGLE_CLIENT_ID,
        "client_secret": Config.GOOGLE_CLIENT_SECRET,
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "redirect_uris": [Config.GOOGLE_REDIRECT_URI],
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs"
    }
}

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
flow = Flow.from_client_config(
    client_config=client_config,
    scopes=["https://www.googleapis.com/auth/userinfo.profile",
            "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri=Config.GOOGLE_REDIRECT_URI
)


# ------------------- APP & EXTENSIONS -------------------
app = Flask(__name__)
app.config.from_object(Config)  # load settings from Config

# JWT setup
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_COOKIE_CSRF_PROTECT"] = False  # Optional for simplicity
jwt = JWTManager(app)


# Mail setup
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 465
app.config["MAIL_USE_SSL"] = True 
app.config["MAIL_USE_TLS"] = False
app.config["MAIL_DEFAULT_SENDER"] = Config.MAIL_USERNAME
app.config["MAIL_USERNAME"] = Config.MAIL_USERNAME
app.config["MAIL_PASSWORD"] = Config.MAIL_PASSWORD
mail = Mail(app)

# Optional: session lifetime from config
app.permanent_session_lifetime = getattr(Config, "SESSION_LIFETIME", timedelta(days=1))



# ------------------- NO CACHE -------------------
@app.after_request
def add_headers(response):
    response.headers["Cache-Control"] = " no-cache, no-store, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


# ------------------- ROUTES -------------------

@app.route('/')
def startPage():
    return render_template("login.html")


@app.route('/signup/')
def signupPage():
    return render_template("signup.html")


@app.route('/home')
@jwt_required(optional=True)
def home():
    claims = get_jwt()
    user_id = claims["userId"]
    fname = claims["fname"]

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, title, content FROM mynotes WHERE userId=? ORDER BY id DESC", (user_id,))
    notes = cursor.fetchall()
    conn.close()

    return render_template("home.html", items=notes, fname=fname)


# ------------------- SIGNUP WITH OTP -------------------
@app.route('/send_otp', methods=["POST"])
def send_otp():
    fname = request.form.get("fname")
    email = request.form.get("email")
    password = request.form.get("password")
    confirm_password = request.form.get("confirm_password")

    if password != confirm_password:
        flash("Passwords do not match!", "error")
        return redirect(url_for("signupPage"))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email=?", (email,))
    if cursor.fetchone():
        conn.close()
        flash("Email already exists!", "error")
        return redirect(url_for("signupPage"))
    conn.close()

    # Save info in session temporarily
    session['fname'] = fname
    session['email'] = email
    session['password'] = generate_password_hash(password)

    otp = random.randint(100000, 999999)
    session['otp'] = str(otp)

    try:
        msg = Message(subject='Your OTP Code', recipients=[email])
        msg.body = f'Your OTP code is: {otp}'
        mail.send(msg)
        flash("OTP sent successfully! Check your email.", "info")
        return render_template("verifyOTP.html", reset=False)
    except Exception as e:
        flash(f"Error sending OTP: {e}", "error")
        return redirect(url_for("signupPage"))


@app.route('/verify_otp', methods=["POST"])
def verify_otp():
    entered_otp = request.form.get("otp")
    if entered_otp == session.get('otp'):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (fname, email, password) VALUES (?, ?, ?)",
                       (session['fname'], session['email'], session['password']))
        conn.commit()
        conn.close()
        flash("Account created successfully! You can now log in.", "success")
        session.clear()
        return redirect(url_for("login"))

    flash("Invalid OTP! Please try again.", "error")
    return render_template("verifyOTP.html")


# ------------------- LOGIN -------------------
@app.route('/login/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email=?", (email,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[3], password):
            token = create_access_token(identity=email, additional_claims={
                "userId": user[0], "fname": user[1], "email": user[2]
            })
            resp = redirect(url_for('home'))
            set_access_cookies(resp, token)
            return resp

        flash("Incorrect email or password!", "error")

    return render_template("login.html")


# ------------------- GOOGLE OAUTH -------------------
@app.route("/google-login")
def google_login():
    authorization_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="select_account"
    )
    session["state"] = state
    return redirect(authorization_url)


@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session.get("state") == request.args.get("state"):
        return "State mismatch. Possible CSRF attack.", 400

    credentials = flow.credentials

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=google_requests.Request(),
        audience=Config.GOOGLE_CLIENT_ID
    )

    email = id_info.get("email")
    fname = id_info.get("name")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email=?", (email,))
    user = cursor.fetchone()

    if not user:
        cursor.execute(
            "INSERT INTO users (fname, email, password) VALUES (?, ?, ?)",
            (fname, email, generate_password_hash(os.urandom(16).hex()))
        )
        conn.commit()
        cursor.execute("SELECT * FROM users WHERE email=?", (email,))
        user = cursor.fetchone()

    conn.close()

    token = create_access_token(identity=email, additional_claims={
        "userId": user[0], "fname": user[1], "email": user[2]
    })
    resp = redirect(url_for("home"))
    set_access_cookies(resp, token)
    return resp


# ------------------- LOGOUT -------------------
@app.route('/logout')
def logout():
    session.clear() 
    resp = redirect(url_for("startPage"))
    unset_jwt_cookies(resp)
    return resp


# ------------------- NOTES ROUTES -------------------
@app.route('/notesApp', methods=['POST'])
@jwt_required()
def notesApp():
    claims = get_jwt()
    title = request.form.get('title')
    content = request.form.get('content')

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO mynotes(userId, title, content) VALUES (?, ?, ?)",
                       (claims["userId"], title, content))
        conn.commit()
        conn.close()
        return redirect(url_for("home"))
    except Exception as e:
        flash(f"Error inserting note: {e}", "error")
        return redirect(url_for("home"))


@app.route('/delete/<int:id>', methods=['POST'])
@jwt_required()
def delete(id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM mynotes WHERE id=?", (id,))
        conn.commit()
        conn.close()
        return redirect(url_for('home'))
    except Exception as e:
        flash(f"Error deleting note: {e}", "error")
        return redirect(url_for("home"))


@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@jwt_required()
def editPage(id):
    claims = get_jwt()
    fname = claims["fname"]
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM mynotes WHERE id=?", (id,))
        notes = cursor.fetchall()
        conn.close()
        return render_template("editNotes.html", items=notes, fname=fname)
    except Exception as e:
        flash(f"Error opening edit page: {e}", "error")
        return redirect(url_for("home"))


@app.route('/update/<int:id>', methods=["POST"])
@jwt_required()
def updateNote(id):
    claims = get_jwt()
    editedTitle = request.form.get('title')
    editedContent = request.form.get('content')

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE mynotes SET title=?, content=? WHERE id=? AND userId=?",
            (editedTitle, editedContent, id, claims["userId"])
        )
        conn.commit()
        conn.close()
        return redirect(url_for('home'))
    except Exception as e:
        flash(f"Error editing note: {e}", "error")
        return redirect(url_for("home"))


@app.route('/closeEdit/')
def closeEdit():
    return redirect(url_for("home"))


# ------------------- PASSWORD RESET -------------------
@app.route("/reset")
def resetPage():
    return render_template("reset.html")


@app.route('/send_reset_otp', methods=["POST"])
def send_reset_otp():
    email = request.form.get("email")
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email=?", (email,))
    user = cursor.fetchone()
    conn.close()

    if not user:
        flash("Email not registered!", "error")
        return redirect(url_for("resetPage"))

    session['reset_email'] = email
    session['otp'] = str(random.randint(100000, 999999))

    try:
        msg = Message(subject='Password Reset OTP', recipients=[email])
        msg.body = f'Your OTP code is: {session["otp"]}'
        mail.send(msg)
        flash("Reset OTP sent! Check your email.", "info")
        return render_template("verifyOTP.html", reset=True)
    except Exception as e:
        flash(f"Error sending OTP: {e}", "error")
        return redirect(url_for("resetPage"))


@app.route('/verify_reset_otp', methods=["POST"])
def verify_reset_otp():
    if request.form.get("otp") == session.get('otp'):
        flash("OTP verified! Please reset your password.", "success")
        return redirect(url_for("new_password_page"))
    flash("Invalid OTP! Please try again.", "error")
    return render_template("verifyOTP.html", reset=True)


@app.route('/new_password', methods=["GET"])
def new_password_page():
    return render_template("resetPassword.html")


@app.route('/reset_password', methods=["POST"])
def reset_password():
    password = request.form.get("password")
    confirm_password = request.form.get("confirm_password")
    email = session.get('reset_email')

    if not email or password != confirm_password:
        flash("Session expired or passwords do not match!", "error")
        return redirect(url_for("login"))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET password=? WHERE email=?",
                   (generate_password_hash(password), email))
    conn.commit()
    conn.close()

    flash("Password updated successfully! You can now log in.", "success")
    session.clear()
    return redirect(url_for("login"))


@app.route('/change_password', methods=['POST'])
@jwt_required()
def change_password():
    claims = get_jwt()
    userId = claims["userId"]
    current = request.form.get('current_password')
    newpass = request.form.get('new_password')
    confirm = request.form.get('confirm_password')

    if not current or not newpass or not confirm:
        flash("All fields are required.", "change_password_error")
        return redirect(url_for('home') + "#popup")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE id=?", (userId,))
    row = cursor.fetchone()

    if not row or not check_password_hash(row[0], current):
        flash("Incorrect Current Password",  "change_password_error")
        return redirect(url_for('home') + "#popup")

    if newpass != confirm:
        flash("Confirm password do not match", "change_password_error")
        return redirect(url_for('home') + "#popup")

    cursor.execute("UPDATE users SET password=? WHERE id=?", (generate_password_hash(newpass), userId))
    conn.commit()
    conn.close()
    flash("Changed password successfully!", "info")
    return redirect(url_for('home'))


# ------------------- RUN -------------------
if __name__ == "__main__":
    init_db()
    app.run(debug=True)

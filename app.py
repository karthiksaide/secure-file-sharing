from flask import Flask, render_template, request, redirect, url_for, session, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from supabase import create_client
import sqlite3
import os
import tempfile
import datetime

app = Flask(__name__)
app.secret_key = "supersecretkey"

# -----------------------------
# Supabase Configuration
# -----------------------------
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
BUCKET_NAME = "encrypted-files"

# -----------------------------
# Database Initialization
# -----------------------------
def init_db():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    password TEXT
                )''')

    # Login logs table
    c.execute('''CREATE TABLE IF NOT EXISTS login_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT,
                    status TEXT,
                    ip_address TEXT,
                    timestamp TEXT
                )''')

    conn.commit()
    conn.close()

init_db()

def get_db():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn

# -----------------------------
# Routes
# -----------------------------
@app.route('/')
def home():
    if 'user' not in session:
        return redirect(url_for('login'))

    files = supabase.storage.from_(BUCKET_NAME).list()
    filenames = [f["name"] for f in files if not f["name"].endswith(".key")]

    return render_template("index.html", files=filenames, user=session['user'])

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])

        conn = get_db()
        try:
            conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
        except:
            return "User already exists"

        return redirect(url_for('login'))

    return render_template("register.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        ip = request.remote_addr
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user and check_password_hash(user['password'], password):
            session['user'] = username

            # Log success
            conn.execute(
                "INSERT INTO login_logs (username, status, ip_address, timestamp) VALUES (?, ?, ?, ?)",
                (username, "SUCCESS", ip, timestamp)
            )
            conn.commit()

            return redirect(url_for('home'))

        # Log failure
        conn.execute(
            "INSERT INTO login_logs (username, status, ip_address, timestamp) VALUES (?, ?, ?, ?)",
            (username, "FAILED", ip, timestamp)
        )
        conn.commit()

        return "Invalid credentials"

    return render_template("login.html")

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

# -----------------------------
# Run App
# -----------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
from flask import Flask, render_template, request, redirect, url_for, session, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from supabase import create_client
import sqlite3
import os
import tempfile

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

    # List files from Supabase
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

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user and check_password_hash(user['password'], password):
            session['user'] = username
            return redirect(url_for('home'))

        return "Invalid credentials"

    return render_template("login.html")

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/upload', methods=['POST'])
def upload():
    if 'user' not in session:
        return redirect(url_for('login'))

    file = request.files['file']

    if file:
        filename = file.filename

        # Read file data
        data = file.read()

        # Hybrid Encryption
        aes_key = Fernet.generate_key()
        cipher_aes = Fernet(aes_key)
        encrypted_data = cipher_aes.encrypt(data)

        # Encrypt AES key using RSA public key
        with open("public.pem", "rb") as f:
            public_key = RSA.import_key(f.read())

        cipher_rsa = PKCS1_OAEP.new(public_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)

        # Upload encrypted file to Supabase
        supabase.storage.from_(BUCKET_NAME).upload(
            filename,
            encrypted_data
        )

        # Upload encrypted AES key
        supabase.storage.from_(BUCKET_NAME).upload(
            filename + ".key",
            encrypted_aes_key
        )

    return redirect(url_for('home'))

@app.route('/download/<filename>')
def download(filename):
    if 'user' not in session:
        return redirect(url_for('login'))

    # Download encrypted file
    encrypted_data = supabase.storage.from_(BUCKET_NAME).download(filename)

    # Download encrypted AES key
    encrypted_aes_key = supabase.storage.from_(BUCKET_NAME).download(filename + ".key")

    # Decrypt AES key
    with open("private.pem", "rb") as f:
        private_key = RSA.import_key(f.read())

    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)

    cipher_aes = Fernet(aes_key)

    # Decrypt file
    decrypted_data = cipher_aes.decrypt(encrypted_data)

    # Create temp file to send
    temp_file = tempfile.NamedTemporaryFile(delete=False)
    temp_file.write(decrypted_data)
    temp_file.close()

    return send_file(temp_file.name, as_attachment=True, download_name=filename)

# -----------------------------
# Run App
# -----------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
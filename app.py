from flask import Flask, render_template, request, redirect, url_for, session, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from supabase import create_client
import os
import tempfile
import datetime
import pytz

app = Flask(__name__)
app.secret_key = "supersecretkey"

# -----------------------------
# Supabase Configuration
# -----------------------------
SUPABASE_URL = os.environ.get("SUPABASE_URL") or "https://iqwxcxcexqqhrzznhzgg.supabase.co"
SUPABASE_KEY = os.environ.get("SUPABASE_KEY") or "YOUR_ANON_KEY_HERE"

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
BUCKET_NAME = "encrypted-files"

# -----------------------------
# Home
# -----------------------------
@app.route('/')
def home():
    if 'user' not in session:
        return redirect(url_for('login'))

    files = supabase.storage.from_(BUCKET_NAME).list()
    filenames = [f["name"] for f in files if not f["name"].endswith(".key")]

    return render_template("index.html", files=filenames, user=session['user'])

# -----------------------------
# Register (Supabase Users Table)
# -----------------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])

        # Check if user exists
        existing = supabase.table("users").select("*").eq("username", username).execute()

        if existing.data:
            return "User already exists"

        supabase.table("users").insert({
            "username": username,
            "password": password
        }).execute()

        return redirect(url_for('login'))

    return render_template("register.html")

# -----------------------------
# Login + Logging (Supabase)
# -----------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        ist = pytz.timezone("Asia/Kolkata")
        timestamp = datetime.datetime.now(ist).strftime("%Y-%m-%d %H:%M:%S")
        ip = request.remote_addr

        result = supabase.table("users").select("*").eq("username", username).execute()

        if result.data:
            user = result.data[0]

            if check_password_hash(user["password"], password):
                session['user'] = username

                supabase.table("login_logs").insert({
                    "username": username,
                    "status": "SUCCESS",
                    "ip_address": ip,
                    "timestamp": timestamp
                }).execute()

                return redirect(url_for('home'))

        # Failed login
        supabase.table("login_logs").insert({
            "username": username,
            "status": "FAILED",
            "ip_address": ip,
            "timestamp": timestamp
        }).execute()

        return "Invalid credentials"

    return render_template("login.html")

# -----------------------------
# Logout
# -----------------------------
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

# -----------------------------
# Upload (Hybrid Encryption + Supabase Storage)
# -----------------------------
@app.route('/upload', methods=['POST'])
def upload():
    if 'user' not in session:
        return redirect(url_for('login'))

    file = request.files['file']

    if file:
        filename = file.filename
        data = file.read()

        # AES Encryption
        aes_key = Fernet.generate_key()
        cipher_aes = Fernet(aes_key)
        encrypted_data = cipher_aes.encrypt(data)

        # RSA Encrypt AES Key
        with open("public.pem", "rb") as f:
            public_key = RSA.import_key(f.read())

        cipher_rsa = PKCS1_OAEP.new(public_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)

        # Upload encrypted file
        supabase.storage.from_(BUCKET_NAME).upload(
            path=filename,
            file=encrypted_data,
            file_options={"upsert": "true"}
        )

        # Upload encrypted AES key
        supabase.storage.from_(BUCKET_NAME).upload(
            path=filename + ".key",
            file=encrypted_aes_key,
            file_options={"upsert": "true"}
        )

    return redirect(url_for('home'))

# -----------------------------
# Download
# -----------------------------
@app.route('/download/<filename>')
def download(filename):
    if 'user' not in session:
        return redirect(url_for('login'))

    encrypted_data = supabase.storage.from_(BUCKET_NAME).download(filename)
    encrypted_aes_key = supabase.storage.from_(BUCKET_NAME).download(filename + ".key")

    with open("private.pem", "rb") as f:
        private_key = RSA.import_key(f.read())

    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)

    cipher_aes = Fernet(aes_key)
    decrypted_data = cipher_aes.decrypt(encrypted_data)

    temp_file = tempfile.NamedTemporaryFile(delete=False)
    temp_file.write(decrypted_data)
    temp_file.close()

    return send_file(temp_file.name, as_attachment=True, download_name=filename)

# -----------------------------
# Run (Render Compatible)
# -----------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
from flask import Flask, render_template, request, redirect, url_for, session, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import sqlite3
import os
import uuid
import pyqrcode
import datetime

app = Flask(__name__)
app.secret_key = "supersecretkey"

# Ensure folders exist
if not os.path.exists("uploads"):
    os.makedirs("uploads")

# Database connection
def get_db():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def home():
    if 'user' not in session:
        return redirect(url_for('login'))

    files = [f for f in os.listdir("uploads") if not f.endswith(".key") and not f.endswith("_qr.png")]
    return render_template("index.html", files=files, user=session['user'])

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
        filepath = os.path.join("uploads", file.filename)
        file.save(filepath)

        # Hybrid Encryption
        aes_key = Fernet.generate_key()
        cipher_aes = Fernet(aes_key)

        with open(filepath, "rb") as f:
            data = f.read()

        encrypted_data = cipher_aes.encrypt(data)

        with open(filepath, "wb") as f:
            f.write(encrypted_data)

        # Encrypt AES key with RSA public key
        with open("public.pem", "rb") as f:
            public_key = RSA.import_key(f.read())

        cipher_rsa = PKCS1_OAEP.new(public_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)

        with open(filepath + ".key", "wb") as f:
            f.write(encrypted_aes_key)

        # Generate secure token (5 min expiry)
        token = str(uuid.uuid4())
        expiry = datetime.datetime.now() + datetime.timedelta(minutes=5)

        with open("tokens.txt", "a") as f:
            f.write(f"{token},{file.filename},{expiry}\n")

        # Generate QR Code
        download_link = request.host_url + "secure_download/" + token
        qr = pyqrcode.create(download_link)
        qr.png(os.path.join("uploads", file.filename + "_qr.png"), scale=5)

    return redirect(url_for('home'))

@app.route('/static_qr/<filename>')
def show_qr(filename):
    qr_path = os.path.join("uploads", filename + "_qr.png")
    if os.path.exists(qr_path):
        return send_file(qr_path, mimetype='image/png')
    return "QR not found" 

@app.route('/download/<filename>')
def download(filename):
    if 'user' not in session:
        return redirect(url_for('login'))

    filepath = os.path.join("uploads", filename)

    # Decrypt AES key
    with open(filepath + ".key", "rb") as f:
        encrypted_aes_key = f.read()

    with open("private.pem", "rb") as f:
        private_key = RSA.import_key(f.read())

    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)

    cipher_aes = Fernet(aes_key)

    # Decrypt file
    with open(filepath, "rb") as f:
        encrypted_data = f.read()

    decrypted_data = cipher_aes.decrypt(encrypted_data)

    temp_path = os.path.join("uploads", "temp_" + filename)

    with open(temp_path, "wb") as f:
        f.write(decrypted_data)

    return send_file(temp_path, as_attachment=True)

@app.route('/secure_download/<token>')
def secure_download(token):
    if not os.path.exists("tokens.txt"):
        return "Invalid Link"

    with open("tokens.txt", "r") as f:
        lines = f.readlines()

    for line in lines:
        saved_token, filename, expiry = line.strip().split(",")

        if saved_token == token:
            expiry_time = datetime.datetime.fromisoformat(expiry)

            if datetime.datetime.now() > expiry_time:
                return "Link Expired"

            # Directly call download function
            session['user'] = "qr_user"
            return download(filename)

    return "Invalid Link"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
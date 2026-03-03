from flask import Flask, render_template, request, redirect, session
from supabase import create_client, Client
import os
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "super-secret-key"

# ---------------- ENV CONFIG ----------------
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
PRIVATE_KEY_DATA = os.environ.get("PRIVATE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise Exception("Supabase environment variables missing")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ---------------- REGISTER ----------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        existing = supabase.table("users").select("*").eq("username", username).execute()
        if existing.data:
            return "User already exists"

        hashed_password = generate_password_hash(password)

        supabase.table("users").insert({
            "username": username,
            "password": hashed_password
        }).execute()

        return redirect("/")

    return render_template("register.html")

# ---------------- LOGIN ----------------
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        result = supabase.table("users").select("*").eq("username", username).execute()

        if result.data and check_password_hash(result.data[0]["password"], password):
            session["user"] = username
            return redirect("/dashboard")

        return "Invalid credentials"

    return render_template("login.html")

# ---------------- DASHBOARD ----------------
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")

    result = supabase.table("files") \
        .select("*") \
        .eq("username", session["user"]) \
        .execute()

    filenames = [f["filename"] for f in result.data] if result.data else []

    return render_template(
        "index.html",
        files=filenames,
        user=session["user"]
    )

# ---------------- UPLOAD ----------------
@app.route("/upload", methods=["POST"])
def upload():
    if "user" not in session:
        return redirect("/")

    file = request.files["file"]
    filename = file.filename
    file_bytes = file.read()

    # Upload to storage
    supabase.storage.from_("encrypted-files").upload(
        f"{session['user']}/{filename}",
        file_bytes,
        {"content-type": "application/octet-stream"}
    )

    # Encrypt dummy AES key
    private_key = RSA.import_key(PRIVATE_KEY_DATA.encode())
    public_key = private_key.publickey()
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_key = cipher_rsa.encrypt(b"dummy_aes_key")

    # Save metadata with owner
    supabase.table("files").insert({
        "filename": filename,
        "encrypted_key": base64.b64encode(encrypted_key).decode(),
        "username": session["user"]
    }).execute()

    return redirect("/dashboard")

# ---------------- DOWNLOAD ----------------
@app.route("/download/<filename>")
def download(filename):
    if "user" not in session:
        return redirect("/")

    result = supabase.table("files") \
        .select("*") \
        .eq("filename", filename) \
        .eq("username", session["user"]) \
        .execute()

    if not result.data:
        return "Unauthorized or file not found", 403

    signed = supabase.storage.from_("encrypted-files") \
        .create_signed_url(f"{session['user']}/{filename}", 60)

    if not signed or "signedURL" not in signed:
        return "Could not generate signed URL", 500

    return redirect(signed["signedURL"])

# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
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
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")   # MUST be SERVICE ROLE KEY
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

    result = supabase.table("files").select("*").execute()

    filenames = []
    if result.data:
        filenames = [f["filename"] for f in result.data]

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

    # Upload file to Supabase Storage
    supabase.storage.from_("encrypted-files").upload(filename, file)

    if not PRIVATE_KEY_DATA:
        return "Private key not configured", 500

    private_key = RSA.import_key(PRIVATE_KEY_DATA.encode())
    public_key = private_key.publickey()

    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_key = cipher_rsa.encrypt(b"dummy_aes_key")

    supabase.table("files").insert({
        "filename": filename,
        "encrypted_key": base64.b64encode(encrypted_key).decode()
    }).execute()

    return redirect("/dashboard")


# ---------------- DOWNLOAD ----------------
@app.route("/download/<filename>")
def download(filename):
    if "user" not in session:
        return redirect("/")

    if not PRIVATE_KEY_DATA:
        return "Private key not configured", 500

    private_key = RSA.import_key(PRIVATE_KEY_DATA.encode())
    cipher_rsa = PKCS1_OAEP.new(private_key)

    result = supabase.table("files").select("*").eq("filename", filename).execute()

    if not result.data:
        return "File not found", 404

    encrypted_key = base64.b64decode(result.data[0]["encrypted_key"])
    cipher_rsa.decrypt(encrypted_key)  # verification step

    signed = supabase.storage.from_("encrypted-files").create_signed_url(filename, 60)

    if not signed or "signedURL" not in signed:
        return "Could not generate signed URL", 500

    return redirect(signed["signedURL"])


# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    app.run()
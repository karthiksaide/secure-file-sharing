from flask import Flask, render_template, request, redirect, session
from supabase import create_client, Client
import os
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

app = Flask(__name__)
app.secret_key = "your-secret-key"

# 🔹 Supabase Config (Render Environment Variables)
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")  # ✅ Must be SERVICE ROLE KEY

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)


# ---------------- LOGIN ----------------
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        result = supabase.table("users").select("*").eq("username", username).execute()

        if result.data and result.data[0]["password"] == password:
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
    return render_template("dashboard.html", files=result.data)


# ---------------- UPLOAD ----------------
@app.route("/upload", methods=["POST"])
def upload():
    if "user" not in session:
        return redirect("/")

    file = request.files["file"]
    filename = file.filename

    # ✅ Upload file directly to Supabase Storage
    supabase.storage.from_("encrypted-files").upload(filename, file)

    # 🔐 Get PRIVATE KEY from environment
    private_key_data = os.environ.get("PRIVATE_KEY")
    if not private_key_data:
        return "Private key missing", 500

    private_key = RSA.import_key(private_key_data.encode())
    public_key = private_key.publickey()

    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_key = cipher_rsa.encrypt(b"dummy_aes_key")

    # Save encrypted key in database
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

    private_key_data = os.environ.get("PRIVATE_KEY")
    if not private_key_data:
        return "Private key not found in environment variables", 500

    private_key = RSA.import_key(private_key_data.encode())
    cipher_rsa = PKCS1_OAEP.new(private_key)

    # Get encrypted AES key from DB
    result = supabase.table("files").select("*").eq("filename", filename).execute()
    if not result.data:
        return "File not found in database", 404

    encrypted_key = base64.b64decode(result.data[0]["encrypted_key"])

    # Decrypt AES key (verification step)
    cipher_rsa.decrypt(encrypted_key)

    # Generate signed URL (valid 60 seconds)
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
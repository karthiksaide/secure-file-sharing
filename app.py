from flask import Flask, render_template, request, redirect, session
from supabase import create_client, Client
import os
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "super-secret-key"

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
PRIVATE_KEY_DATA = os.environ.get("PRIVATE_KEY")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)


# ---------------- REGISTER ----------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        existing = supabase.table("users").select("*").eq("username", username).execute()
        if existing.data:
            return "Username already exists"

        hashed = generate_password_hash(password)

        supabase.table("users").insert({
            "username": username,
            "password": hashed
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

    user = session["user"]

    own_files = supabase.table("files").select("*").eq("username", user).execute()

    shared_permissions = supabase.table("file_permissions") \
        .select("*") \
        .eq("shared_with", user) \
        .execute()

    shared_files = []
    if shared_permissions.data:
        for permission in shared_permissions.data:
            shared_files.append({
                "filename": permission["filename"],
                "owner": permission["owner"],
                "shared_at": permission["created_at"]
            })

    users = supabase.table("users").select("username").execute()
    all_users = [u["username"] for u in users.data if u["username"] != user]

    return render_template(
        "index.html",
        own_files=own_files.data if own_files.data else [],
        shared_files=shared_files,
        all_users=all_users,
        user=user
    )


# ---------------- UPLOAD ----------------
@app.route("/upload", methods=["POST"])
def upload():
    if "user" not in session:
        return redirect("/")

    file = request.files["file"]
    filename = file.filename
    file_bytes = file.read()
    file_size = len(file_bytes)

    # Prevent duplicate filename + same size
    existing = supabase.table("files") \
        .select("*") \
        .eq("filename", filename) \
        .eq("username", session["user"]) \
        .execute()

    if existing.data:
        for f in existing.data:
            if f.get("file_size") == file_size:
                return "Same file already uploaded"

    supabase.storage.from_("encrypted-files").upload(
        f"{session['user']}/{filename}",
        file_bytes,
        {"content-type": "application/octet-stream"}
    )

    private_key = RSA.import_key(PRIVATE_KEY_DATA.encode())
    public_key = private_key.publickey()
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_key = cipher_rsa.encrypt(b"dummy_aes_key")

    supabase.table("files").insert({
        "filename": filename,
        "file_size": file_size,
        "encrypted_key": base64.b64encode(encrypted_key).decode(),
        "username": session["user"]
    }).execute()

    return redirect("/dashboard")


# ---------------- DELETE ----------------
@app.route("/delete/<filename>", methods=["POST"])
def delete(filename):
    if "user" not in session:
        return redirect("/")

    user = session["user"]

    own = supabase.table("files") \
        .select("*") \
        .eq("filename", filename) \
        .eq("username", user) \
        .execute()

    if not own.data:
        return "Unauthorized", 403

    # Remove from storage
    supabase.storage.from_("encrypted-files").remove([f"{user}/{filename}"])

    # Remove from database
    supabase.table("files").delete().eq("filename", filename).eq("username", user).execute()
    supabase.table("file_permissions").delete().eq("filename", filename).eq("owner", user).execute()

    return redirect("/dashboard")


# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
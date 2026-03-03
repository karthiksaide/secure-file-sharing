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
            return "User already exists"

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

    # Own files
    own_files = supabase.table("files") \
        .select("*") \
        .eq("username", user) \
        .execute()

    # Shared files
    shared = supabase.table("file_permissions") \
        .select("*") \
        .eq("shared_with", user) \
        .execute()

    shared_filenames = [s["filename"] for s in shared.data] if shared.data else []

    shared_files = []
    if shared_filenames:
        shared_files = supabase.table("files") \
            .select("*") \
            .in_("filename", shared_filenames) \
            .execute().data

    # Get all users for checkbox display
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
        "encrypted_key": base64.b64encode(encrypted_key).decode(),
        "username": session["user"]
    }).execute()

    return redirect("/dashboard")


# ---------------- SHARE ----------------
@app.route("/share/<filename>", methods=["POST"])
def share(filename):
    if "user" not in session:
        return redirect("/")

    selected_users = request.form.getlist("users")

    for u in selected_users:
        supabase.table("file_permissions").insert({
            "filename": filename,
            "owner": session["user"],
            "shared_with": u
        }).execute()

    return redirect("/dashboard")


# ---------------- DOWNLOAD ----------------
@app.route("/download/<filename>")
def download(filename):
    if "user" not in session:
        return redirect("/")

    user = session["user"]

    # Check ownership
    own = supabase.table("files") \
        .select("*") \
        .eq("filename", filename) \
        .eq("username", user) \
        .execute()

    # Check shared permission
    shared = supabase.table("file_permissions") \
        .select("*") \
        .eq("filename", filename) \
        .eq("shared_with", user) \
        .execute()

    if not own.data and not shared.data:
        return "Unauthorized", 403

    signed = supabase.storage.from_("encrypted-files") \
        .create_signed_url(f"{own.data[0]['username'] if own.data else shared.data[0]['owner']}/{filename}", 60)

    return redirect(signed["signedURL"])


# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
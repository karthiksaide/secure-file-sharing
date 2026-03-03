from flask import Flask, render_template, request, redirect, session
from supabase import create_client
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

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)


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

    shared_files = shared_permissions.data if shared_permissions.data else []

    users = supabase.table("users").select("username").execute()
    all_users = [u["username"] for u in users.data if u["username"] != user]

    return render_template(
        "index.html",
        own_files=own_files.data if own_files.data else [],
        shared_files=shared_files,
        all_users=all_users,
        user=user
    )


@app.route("/upload", methods=["POST"])
def upload():
    if "user" not in session:
        return redirect("/")

    file = request.files["file"]
    filename = file.filename
    file_bytes = file.read()
    file_size = len(file_bytes)

    existing = supabase.table("files") \
        .select("*") \
        .eq("filename", filename) \
        .eq("username", session["user"]) \
        .execute()

    if existing.data:
        return "File already exists"

    supabase.storage.from_("encrypted-files").upload(
        f"{session['user']}/{filename}",
        file_bytes,
        {"content-type": "application/octet-stream"}
    )

    supabase.table("files").insert({
        "filename": filename,
        "file_size": file_size,
        "username": session["user"]
    }).execute()

    return redirect("/dashboard")


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


@app.route("/delete/<filename>", methods=["POST"])
def delete(filename):
    if "user" not in session:
        return redirect("/")

    user = session["user"]

    supabase.storage.from_("encrypted-files").remove([f"{user}/{filename}"])
    supabase.table("files").delete().eq("filename", filename).eq("username", user).execute()
    supabase.table("file_permissions").delete().eq("filename", filename).eq("owner", user).execute()

    return redirect("/dashboard")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
from flask import Flask, render_template, request, redirect, session, jsonify
from supabase import create_client
import os, base64
from datetime import datetime, timezone, timedelta
from werkzeug.security import generate_password_hash, check_password_hash

IST = timezone(timedelta(hours=5, minutes=30))

def utc_to_ist(utc_str):
    if not utc_str: return ""
    try:
        dt = datetime.fromisoformat(utc_str.replace("Z", "+00:00"))
        return dt.astimezone(IST).strftime("%d %b %Y at %I:%M %p")
    except: return ""

app = Flask(__name__)
app.secret_key = "filelite-secret"

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)


@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = supabase.table("users").select("*").eq("username", username).execute()
        if not user.data:
            return render_template("login.html", error="User does not exist")
        if not check_password_hash(user.data[0]["password"], password):
            return render_template("login.html", error="Incorrect password")
        session["user"] = username
        return redirect("/dashboard")
    return render_template("login.html")


@app.route("/login_check", methods=["POST"])
def login_check():
    username = request.form["username"]
    password = request.form["password"]
    user = supabase.table("users").select("*").eq("username", username).execute()
    if not user.data:
        return jsonify({"success": False, "error": "User does not exist"})
    if not check_password_hash(user.data[0]["password"], password):
        return jsonify({"success": False, "error": "Incorrect password"})
    session["user"] = username
    return jsonify({"success": True})


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        public_key = request.form.get("public_key", "")
        encrypted_private_key = request.form.get("encrypted_private_key", "")
        exists = supabase.table("users").select("*").eq("username", username).execute()
        if exists.data:
            return render_template("register.html", error="Username already exists")
        hashed = generate_password_hash(password)
        supabase.table("users").insert({
            "username": username,
            "password": hashed,
            "public_key": public_key,
            "encrypted_private_key": encrypted_private_key
        }).execute()
        return redirect("/")
    return render_template("register.html")


@app.route("/get_encrypted_private_key/<username>")
def get_encrypted_private_key(username):
    user = supabase.table("users").select("encrypted_private_key").eq("username", username).execute()
    if not user.data or not user.data[0]["encrypted_private_key"]:
        return jsonify({}), 404
    return jsonify({"encrypted_private_key": user.data[0]["encrypted_private_key"]})


@app.route("/get_public_key/<username>")
def get_public_key(username):
    if "user" not in session:
        return "Unauthorized", 403
    user = supabase.table("users").select("public_key").eq("username", username).execute()
    if not user.data or not user.data[0]["public_key"]:
        return "Not found", 404
    return user.data[0]["public_key"]


@app.route("/check_user/<username>")
def check_user(username):
    if "user" not in session:
        return jsonify({}), 403
    user = supabase.table("users").select("username").eq("username", username).execute()
    if not user.data:
        return jsonify({}), 404
    return jsonify({"exists": True})


@app.route("/get_file_key/<path:filename>")
def get_file_key(filename):
    if "user" not in session:
        return jsonify({}), 403
    user = session["user"]
    rec = supabase.table("files").select("encrypted_key, iv")\
        .eq("filename", filename).eq("username", user).execute()
    if not rec.data:
        return jsonify({}), 404
    return jsonify({"encrypted_key": rec.data[0]["encrypted_key"], "iv": rec.data[0]["iv"]})


@app.route("/get_files_size", methods=["POST"])
def get_files_size():
    if "user" not in session:
        return jsonify({}), 403
    data = request.get_json()
    filenames = data.get("filenames", [])
    total_bytes = 0
    for filename in filenames:
        rec = supabase.table("files").select("filesize")\
            .eq("filename", filename).eq("username", session["user"]).execute()
        if rec.data and rec.data[0]["filesize"]:
            total_bytes += rec.data[0]["filesize"]
    return jsonify({"total_mb": total_bytes / (1024 * 1024)})


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")
    user = session["user"]
    own_files = supabase.table("files").select("*").eq("username", user).execute()
    shared_permissions = supabase.table("file_permissions").select("*").eq("shared_with", user).execute()
    shared_files = []
    if shared_permissions.data:
        for f in shared_permissions.data:
            shared_files.append({
                "filename": f["filename"],
                "owner": f["owner"],
                "shared_at": utc_to_ist(f.get("created_at", ""))
            })
    users = supabase.table("users").select("username").execute()
    all_users = [u["username"] for u in users.data if u["username"] != user]
    return render_template("index.html",
        own_files=own_files.data if own_files.data else [],
        shared_files=shared_files,
        all_users=all_users,
        user=user)


@app.route("/upload", methods=["POST"])
def upload():
    if "user" not in session:
        return redirect("/")
    files = request.files.getlist("file")
    encrypted_key = request.form.get("encrypted_key")
    iv = request.form.get("iv")
    filesize = request.form.get("filesize", 0)
    for file in files:
        if file.filename == "": continue
        filename = file.filename
        file_bytes = file.read()
        existing = supabase.table("files").select("*")\
            .eq("filename", filename).eq("username", session["user"]).execute()
        if existing.data:
            continue
        supabase.storage.from_("encrypted-files").upload(
            f"{session['user']}/{filename}", file_bytes, {"upsert": "true"}
        )
        supabase.table("files").insert({
            "filename": filename,
            "username": session["user"],
            "encrypted_key": encrypted_key,
            "iv": iv,
            "filesize": int(filesize)
        }).execute()
    return redirect("/dashboard")


@app.route("/share/<path:filename>", methods=["POST"])
def share(filename):
    if "user" not in session:
        return redirect("/")
    data = request.get_json()
    users_list = data.get("users", [])
    iv = data.get("iv", "")
    for entry in users_list:
        u = entry["user"]
        enc_key = entry["encrypted_key"]
        existing = supabase.table("file_permissions").select("*")\
            .eq("filename", filename).eq("owner", session["user"])\
            .eq("shared_with", u).execute()
        if not existing.data:
            supabase.table("file_permissions").insert({
                "filename": filename,
                "owner": session["user"],
                "shared_with": u,
                "encrypted_key": enc_key,
                "iv": iv
            }).execute()
    return jsonify({"status": "ok"})


@app.route("/download_encrypted/<path:filename>")
def download_encrypted(filename):
    if "user" not in session:
        return jsonify({}), 403
    user = session["user"]
    owner = request.args.get("owner", user)
    if owner == user:
        rec = supabase.table("files").select("encrypted_key, iv")\
            .eq("filename", filename).eq("username", user).execute()
        if not rec.data: return jsonify({}), 403
        encrypted_key = rec.data[0]["encrypted_key"]
        iv = rec.data[0]["iv"]
    else:
        shared = supabase.table("file_permissions").select("*")\
            .eq("filename", filename).eq("shared_with", user).execute()
        if not shared.data: return jsonify({}), 403
        encrypted_key = shared.data[0]["encrypted_key"]
        iv = shared.data[0]["iv"]
    file_bytes = supabase.storage.from_("encrypted-files").download(f"{owner}/{filename}")
    file_b64 = base64.b64encode(file_bytes).decode()
    return jsonify({"file_b64": file_b64, "encrypted_key": encrypted_key, "iv": iv})


@app.route("/delete/<path:filename>", methods=["POST"])
def delete(filename):
    if "user" not in session: return redirect("/")
    user = session["user"]
    supabase.storage.from_("encrypted-files").remove([f"{user}/{filename}"])
    supabase.table("files").delete().eq("filename", filename).eq("username", user).execute()
    supabase.table("file_permissions").delete().eq("filename", filename).eq("owner", user).execute()
    return jsonify({"status": "ok"})


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/about")
def about():
    return render_template("about.html")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
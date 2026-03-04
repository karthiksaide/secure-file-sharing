from flask import Flask, render_template, request, redirect, session, send_file
from supabase import create_client
import os
import io
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))

def utc_to_ist(utc_str):
    if not utc_str:
        return ""
    try:
        dt = datetime.fromisoformat(utc_str.replace("Z", "+00:00"))
        dt_ist = dt.astimezone(IST)
        return dt_ist.strftime("%d %b %Y at %I:%M %p")
    except:
        return ""
from werkzeug.security import generate_password_hash, check_password_hash

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
        if user.data and check_password_hash(user.data[0]["password"], password):
            session["user"] = username
            return redirect("/dashboard")
        return render_template("login.html", error="Invalid username or password")
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        exists = supabase.table("users").select("*").eq("username", username).execute()
        if exists.data:
            return render_template("register.html", error="Username already exists")
        hashed = generate_password_hash(password)
        supabase.table("users").insert({
            "username": username,
            "password": hashed
        }).execute()
        return redirect("/")
    return render_template("register.html")


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")

    user = session["user"]

    # Own files
    own_files = supabase.table("files").select("*").eq("username", user).execute()

    # Shared with me — include created_at for timestamp
    shared_permissions = supabase.table("file_permissions").select("*").eq("shared_with", user).execute()

    shared_files = []
    if shared_permissions.data:
        for f in shared_permissions.data:
            shared_files.append({
                "filename": f["filename"],
                "owner": f["owner"],
                "shared_at": utc_to_ist(f.get("created_at", ""))
            })

    # All other users for share modal
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

    # Get multiple files
    files = request.files.getlist("file")

    if not files:
        return redirect("/dashboard")

    errors = []

    for file in files:
        if file.filename == "":
            continue

        filename = file.filename
        file_bytes = file.read()

        # Check duplicate
        existing = supabase.table("files").select("*")\
            .eq("filename", filename)\
            .eq("username", session["user"]).execute()

        if existing.data:
            errors.append(f"'{filename}' already exists")
            continue

        # Upload to Supabase storage
        supabase.storage.from_("encrypted-files").upload(
            f"{session['user']}/{filename}",
            file_bytes,
            {"upsert": "true"}
        )

        # Save record in DB
        supabase.table("files").insert({
            "filename": filename,
            "username": session["user"]
        }).execute()

    if errors:
        # Re-render dashboard with error
        own_files = supabase.table("files").select("*").eq("username", session["user"]).execute()
        shared_permissions = supabase.table("file_permissions").select("*").eq("shared_with", session["user"]).execute()
        shared_files = []
        if shared_permissions.data:
            for f in shared_permissions.data:
                shared_files.append({"filename": f["filename"], "owner": f["owner"], "shared_at": utc_to_ist(f.get("created_at", ""))})
        users = supabase.table("users").select("username").execute()
        all_users = [u["username"] for u in users.data if u["username"] != session["user"]]
        return render_template(
            "index.html",
            own_files=own_files.data if own_files.data else [],
            shared_files=shared_files,
            all_users=all_users,
            user=session["user"],
            error=", ".join(errors)
        )

    return redirect("/dashboard")


@app.route("/share/<path:filename>", methods=["POST"])
def share(filename):
    if "user" not in session:
        return redirect("/")

    selected_users = request.form.getlist("users")

    for u in selected_users:
        # Avoid duplicates
        existing = supabase.table("file_permissions").select("*")\
            .eq("filename", filename)\
            .eq("owner", session["user"])\
            .eq("shared_with", u).execute()
        if not existing.data:
            supabase.table("file_permissions").insert({
                "filename": filename,
                "owner": session["user"],
                "shared_with": u
            }).execute()

    return redirect("/dashboard")


@app.route("/download/<path:filename>")
def download(filename):
    if "user" not in session:
        return redirect("/")

    user = session["user"]

    # Check ownership
    own = supabase.table("files").select("*")\
        .eq("filename", filename)\
        .eq("username", user).execute()

    if own.data:
        owner = user
    else:
        # Check shared permission
        shared = supabase.table("file_permissions").select("*")\
            .eq("filename", filename)\
            .eq("shared_with", user).execute()
        if not shared.data:
            return "Unauthorized", 403
        owner = shared.data[0]["owner"]

    # Download file bytes from Supabase storage
    file_bytes = supabase.storage.from_("encrypted-files").download(
        f"{owner}/{filename}"
    )

    # Force download with correct filename — fixes PNG opening fullscreen
    return send_file(
        io.BytesIO(file_bytes),
        as_attachment=True,
        download_name=filename
    )


@app.route("/delete/<path:filename>", methods=["POST"])
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


@app.route("/about")
def about():
    return "<h2>FileLite</h2><p>Secure cloud file sharing system.</p>"


@app.route("/help")
def help():
    return "<h2>Help</h2><p>Upload and share files securely.</p>"


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)

from flask import Flask, render_template, request, redirect, session, url_for
from supabase import create_client
import os
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

    # Fetch user's own files
    own_files = supabase.table("files").select("*").eq("username", user).execute()

    # Fetch files shared with this user
    shared_permissions = supabase.table("file_permissions").select("*").eq("shared_with", user).execute()

    shared_files = []
    if shared_permissions.data:
        for f in shared_permissions.data:
            shared_files.append({
                "filename": f["filename"],
                "owner": f["owner"]
            })

    # All other users (for share dropdown)
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

    file = request.files.get("file")

    if not file or file.filename == "":
        return redirect("/dashboard")

    filename = file.filename
    file_bytes = file.read()

    # Check if file already exists for this user
    existing = supabase.table("files").select("*").eq("filename", filename).eq("username", session["user"]).execute()
    if existing.data:
        # Re-fetch dashboard data to show error
        own_files = supabase.table("files").select("*").eq("username", session["user"]).execute()
        shared_permissions = supabase.table("file_permissions").select("*").eq("shared_with", session["user"]).execute()
        shared_files = []
        if shared_permissions.data:
            for f in shared_permissions.data:
                shared_files.append({"filename": f["filename"], "owner": f["owner"]})
        users = supabase.table("users").select("username").execute()
        all_users = [u["username"] for u in users.data if u["username"] != session["user"]]
        return render_template(
            "index.html",
            own_files=own_files.data if own_files.data else [],
            shared_files=shared_files,
            all_users=all_users,
            user=session["user"],
            error="A file with that name already exists!"
        )

    # Upload to Supabase storage
    supabase.storage.from_("encrypted-files").upload(
        f"{session['user']}/{filename}",
        file_bytes,
        {"upsert": "true"}
    )

    # Save file record in DB
    supabase.table("files").insert({
        "filename": filename,
        "username": session["user"]
    }).execute()

    return redirect("/dashboard")


@app.route("/share/<path:filename>", methods=["POST"])
def share(filename):
    if "user" not in session:
        return redirect("/")

    selected_users = request.form.getlist("users")

    for u in selected_users:
        # Avoid duplicate share entries
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

    # Check if user owns the file
    own = supabase.table("files").select("*").eq("filename", filename).eq("username", user).execute()

    if own.data:
        owner = user
    else:
        # Check if file was shared with user
        shared = supabase.table("file_permissions").select("*")\
            .eq("filename", filename)\
            .eq("shared_with", user).execute()

        if not shared.data:
            return "Unauthorized", 403

        owner = shared.data[0]["owner"]

    signed = supabase.storage.from_("encrypted-files").create_signed_url(
        f"{owner}/{filename}", 60
    )

    return redirect(signed["signedURL"])


@app.route("/delete/<path:filename>", methods=["POST"])
def delete(filename):
    if "user" not in session:
        return redirect("/")

    user = session["user"]

    # Remove from storage
    supabase.storage.from_("encrypted-files").remove([f"{user}/{filename}"])

    # Remove from files table
    supabase.table("files").delete().eq("filename", filename).eq("username", user).execute()

    # Remove all shared permissions for this file
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

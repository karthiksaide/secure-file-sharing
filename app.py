from flask import Flask, render_template, request, redirect, session, jsonify
from supabase import create_client
import os
import base64
from datetime import datetime

app = Flask(__name__)
app.secret_key = "secret123"

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# ---------------- LOGIN ----------------

@app.route("/", methods=["GET","POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        user = supabase.table("users").select("*").eq("username", username).execute()

        if not user.data:
            return "User not found"

        if user.data[0]["password"] != password:
            return "Wrong password"

        session["user"] = username

        return redirect("/dashboard")

    return render_template("login.html")


# ---------------- REGISTER ----------------

@app.route("/register", methods=["GET","POST"])
def register():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        exists = supabase.table("users").select("*").eq("username", username).execute()

        if exists.data:
            return "User exists"

        supabase.table("users").insert({
            "username": username,
            "password": password
        }).execute()

        return redirect("/")

    return render_template("register.html")


# ---------------- DASHBOARD ----------------

@app.route("/dashboard")
def dashboard():

    if "user" not in session:
        return redirect("/")

    user = session["user"]

    files = supabase.table("files").select("*").eq("username", user).execute()

    shared = supabase.table("file_permissions").select("*").eq("shared_with", user).execute()

    users = supabase.table("users").select("username").execute()

    user_list = []

    for u in users.data:
        if u["username"] != user:
            user_list.append(u["username"])

    return render_template(
        "index.html",
        own_files = files.data,
        shared_files = shared.data,
        all_users = user_list,
        user = user
    )


# ---------------- UPLOAD ----------------

@app.route("/upload", methods=["POST"])
def upload():

    if "user" not in session:
        return redirect("/")

    file = request.files["file"]

    filename = file.filename

    data = file.read()

    supabase.storage.from_("encrypted-files").upload(
        f"{session['user']}/{filename}",
        data,
        {"upsert": "true"}
    )

    supabase.table("files").insert({
        "filename": filename,
        "username": session["user"]
    }).execute()

    return redirect("/dashboard")


# ---------------- SHARE ----------------

@app.route("/share/<path:filename>", methods=["POST"])
def share(filename):

    if "user" not in session:
        return jsonify({"error": "not logged in"}),403

    data = request.get_json()

    users = data.get("users", [])

    inserted = 0

    for u in users:

        exists = supabase.table("file_permissions").select("*")\
            .eq("filename", filename)\
            .eq("owner", session["user"])\
            .eq("shared_with", u)\
            .execute()

        if not exists.data:

            supabase.table("file_permissions").insert({
                "filename": filename,
                "owner": session["user"],
                "shared_with": u
            }).execute()

            inserted += 1

    return jsonify({"status":"ok","inserted":inserted})


# ---------------- DOWNLOAD ----------------

@app.route("/download/<path:filename>")
def download(filename):

    if "user" not in session:
        return redirect("/")

    owner = request.args.get("owner", session["user"])

    file_bytes = supabase.storage.from_("encrypted-files").download(f"{owner}/{filename}")

    return file_bytes


# ---------------- DELETE ----------------

@app.route("/delete/<path:filename>", methods=["POST"])
def delete(filename):

    if "user" not in session:
        return redirect("/")

    user = session["user"]

    supabase.storage.from_("encrypted-files").remove([f"{user}/{filename}"])

    supabase.table("files").delete().eq("filename", filename).eq("username", user).execute()

    supabase.table("file_permissions").delete().eq("filename", filename).eq("owner", user).execute()

    return jsonify({"status":"ok"})


# ---------------- LOGOUT ----------------

@app.route("/logout")
def logout():

    session.clear()

    return redirect("/")


# ---------------- HEALTH ----------------

@app.route("/health")
def health():
    return "ok",200


if __name__ == "__main__":

    port = int(os.environ.get("PORT",10000))

    app.run(host="0.0.0.0", port=port)
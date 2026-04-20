#!/usr/bin/env python3"""
CodeAlpha Task 3 - Secure Coding Review
FILE: secure_app.py
Purpose: Remediated version of vulnerable_app.py with all fixes applied.
"""

from flask import Flask, request, escape
import sqlite3, os, subprocess, bcrypt, shlex, secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)   # FIX-01: Random secret at runtime
DB_PATH = "users_secure.db"

# ── FIX-02: Parameterised query ──────────────
@app.route("/login", methods=["POST"])
def login():
    user = request.form.get("username", "")
    pwd  = request.form.get("password", "")
    conn = sqlite3.connect(DB_PATH)
    cur  = conn.execute("SELECT * FROM users WHERE username=?", (user,))
    row  = cur.fetchone()
    conn.close()
    if row and bcrypt.checkpw(pwd.encode(), row[2].encode()):
        return f"Welcome {row[1]}!"
    return "Invalid credentials", 401

# ── FIX-03: Escaped output ───────────────────
@app.route("/greet")
def greet():
    name = escape(request.args.get("name", "Guest"))
    return f"<h1>Hello, {name}!</h1>"

# ── FIX-04: No shell, validated input ────────
ALLOWED_HOSTS = {"localhost", "127.0.0.1", "google.com"}

@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if host not in ALLOWED_HOSTS:
        return "Host not allowed", 400
    result = subprocess.check_output(["ping", "-c", "1", host], text=True)
    return f"<pre>{result}</pre>"

# ── FIX-05: Restricted path ──────────────────
SAFE_DIR = os.path.abspath("./public_files")

@app.route("/file")
def read_file():
    filename = request.args.get("name", "")
    safe_path = os.path.abspath(os.path.join(SAFE_DIR, filename))
    if not safe_path.startswith(SAFE_DIR):
        return "Access denied", 403
    with open(safe_path, "r") as f:
        return f"<pre>{escape(f.read())}</pre>"

# ── FIX-06: No pickle, use JSON ──────────────
import json

@app.route("/load", methods=["POST"])
def load_data():
    data = request.get_json(force=True, silent=True)
    if data is None:
        return "Invalid JSON", 400
    return str(data)

# ── FIX-07: bcrypt hashing ───────────────────
def store_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

# ── FIX-08: No debug in production ───────────
if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5000)

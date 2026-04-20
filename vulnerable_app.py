#!/usr/bin/env python3
"""
CodeAlpha Task 3 - Secure Coding Review
FILE: vulnerable_app.py
Purpose: Intentionally vulnerable Flask app used as the audit target.
         DO NOT deploy this in production.
"""

from flask import Flask, request, render_template_string
import sqlite3, os, subprocess, hashlib, pickle

app = Flask(__name__)
SECRET_KEY = "admin123"          # VULN-01: Hardcoded secret
DB_PATH    = "users.db"

# ── DB setup ──────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""CREATE TABLE IF NOT EXISTS users
                    (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)""")
    conn.execute("INSERT OR IGNORE INTO users VALUES (1,'admin','admin123','admin')")
    conn.execute("INSERT OR IGNORE INTO users VALUES (2,'alice','pass123','user')")
    conn.commit(); conn.close()

# ── VULN-02: SQL Injection ────────────────────
@app.route("/login", methods=["POST"])
def login():
    user = request.form["username"]
    pwd  = request.form["password"]
    conn = sqlite3.connect(DB_PATH)
    # BUG: Direct string interpolation — injectable!
    query = f"SELECT * FROM users WHERE username='{user}' AND password='{pwd}'"
    cur   = conn.execute(query)
    row   = cur.fetchone()
    conn.close()
    if row:
        return f"Welcome {row[1]}! Role: {row[3]}"
    return "Invalid credentials", 401

# ── VULN-03: XSS ─────────────────────────────
@app.route("/greet")
def greet():
    name = request.args.get("name", "Guest")
    # BUG: Unsanitised user input rendered in HTML
    template = f"<h1>Hello, {name}!</h1>"
    return render_template_string(template)

# ── VULN-04: Command Injection ────────────────
@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    # BUG: shell=True with user input
    result = subprocess.check_output(f"ping -c 1 {host}", shell=True, text=True)
    return f"<pre>{result}</pre>"

# ── VULN-05: Path Traversal ───────────────────
@app.route("/file")
def read_file():
    filename = request.args.get("name", "readme.txt")
    # BUG: No path sanitisation
    with open(filename, "r") as f:
        return f"<pre>{f.read()}</pre>"

# ── VULN-06: Insecure Deserialization ─────────
@app.route("/load", methods=["POST"])
def load_data():
    data = request.get_data()
    # BUG: pickle.loads on untrusted data allows RCE
    obj = pickle.loads(data)
    return str(obj)

# ── VULN-07: Weak hashing ─────────────────────
def store_password(password: str) -> str:
    # BUG: MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()

# ── VULN-08: Debug mode in production ─────────
if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)   # BUG: debug=True exposes console

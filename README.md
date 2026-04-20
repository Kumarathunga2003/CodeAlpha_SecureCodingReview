# CodeAlpha_SecureCodingReview

#  CodeAlpha - Secure Coding Review
> **CodeAlpha Cybersecurity Internship | Task 3**

A full security audit of an intentionally vulnerable **Python Flask** web application. Identifies 8 critical vulnerabilities, demonstrates exploits, and provides a fully remediated version with a detailed findings report.

---

## Features
- Intentionally vulnerable app as the audit target
- Manual code review + static analysis methodology
- Detailed report with CWE references for each finding
- Fully remediated secure version of the app
- Covers OWASP Top 10 vulnerabilities

---

## Vulnerabilities Found

| ID       | Vulnerability              | Severity | CWE      |
|----------|----------------------------|----------|----------|
| VULN-01  | Hardcoded Secret Key       | High     | CWE-798  |
| VULN-02  | SQL Injection              | Critical | CWE-89   |
| VULN-03  | Cross-Site Scripting (XSS) | High     | CWE-79   |
| VULN-04  | Command Injection          | Critical | CWE-78   |
| VULN-05  | Path Traversal             | High     | CWE-22   |
| VULN-06  | Insecure Deserialization   | Critical | CWE-502  |
| VULN-07  | Weak Cryptography (MD5)    | High     | CWE-327  |
| VULN-08  | Debug Mode in Production   | Medium   | CWE-489  |

---

## Requirements
- Python 3.7+
- Flask, bcrypt

```bash
pip install flask bcrypt
```

---

## Project Structure

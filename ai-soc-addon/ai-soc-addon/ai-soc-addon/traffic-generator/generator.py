"""
Générateur de trafic "normal" pour entraîner le modèle d'anomalies.
Simule des utilisateurs légitimes qui font des tentatives de login
occasionnelles, avec un mélange réaliste de succès et d'échecs.
"""
import random
import time
import requests

import os
USER_AUTH_URL = os.environ.get("USER_AUTH_URL", "http://user-auth:3000")

# Quelques comptes (la plupart n'existeront pas réellement -> ça génère
# aussi quelques 401 "normaux", ce qui rend le modèle plus réaliste)
CANDIDATE_LOGINS = [
    {"email": "admin@auraweb.com", "password": "Admin@123"},   # compte admin réel du projet
    {"email": "testuser1@example.com", "password": "wrongpass"},
    {"email": "testuser2@example.com", "password": "hello123"},
    {"email": "random@example.com", "password": "azerty"},
]

print("[traffic-generator] Démarrage du trafic normal...")

while True:
    creds = random.choice(CANDIDATE_LOGINS)
    try:
        requests.post(f"{USER_AUTH_URL}/api/auth/login", json=creds, timeout=3)
    except Exception as e:
        print(f"[traffic-generator] erreur requête: {e}")

    # rythme "humain" : entre 1 et 4 requêtes toutes les quelques secondes
    time.sleep(random.uniform(1.5, 4.0))

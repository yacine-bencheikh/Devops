"""
Simulateur d'attaque brute-force sur /api/auth/login.
Attend un délai (le temps que le modèle IA apprenne le trafic normal),
puis envoie une rafale de tentatives de connexion échouées pour
déclencher une anomalie détectable.
"""
import time
import requests

import os
USER_AUTH_URL = os.environ.get("USER_AUTH_URL", "http://user-auth:3000")

# Temps d'attente avant de lancer l'attaque (en secondes).
# Doit être > (WARMUP_SAMPLES * SCRAPE_INTERVAL_SECONDS) du détecteur
# pour laisser le modèle finir son apprentissage. Par défaut 20*5=100s.
WAIT_BEFORE_ATTACK = 60

print(f"[attack-simulator] En attente {WAIT_BEFORE_ATTACK}s avant de lancer l'attaque...")
time.sleep(WAIT_BEFORE_ATTACK)

print("[attack-simulator] 🚨 Lancement de l'attaque brute-force sur /api/auth/login")

for i in range(300):
    try:
        requests.post(
            f"{USER_AUTH_URL}/api/auth/login",
            json={"email": "admin@auraweb.com", "password": f"guess{i}"},
            timeout=2,
        )
    except Exception as e:
        print(f"[attack-simulator] erreur requête: {e}")
    time.sleep(0.02)  # rafale rapide : ~50 req/sec, concentrée sur peu de fenêtres

print("[attack-simulator] Attaque terminée. Le conteneur reste actif sans rien faire.")
while True:
    time.sleep(3600)

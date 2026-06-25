"""
AI Anomaly Detector - "Mini SOC" dashboard
--------------------------------------------
Scrape les métriques Prometheus exposées par user-auth (/metrics),
calcule des features par fenêtre de temps, entraîne un modèle
Isolation Forest sur le trafic "normal", puis score en continu
chaque nouvelle fenêtre pour détecter des anomalies (ex: brute-force).

Tout est servi via une petite interface web (Flask) avec auto-refresh.
"""

import re
import time
import threading
from collections import deque
from datetime import datetime

import requests
from flask import Flask, jsonify, render_template_string
from sklearn.ensemble import IsolationForest
import numpy as np

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
METRICS_URL = "http://user-auth:3000/metrics"
SCRAPE_INTERVAL_SECONDS = 5          # fréquence de lecture des métriques
WARMUP_SAMPLES = 10                  # nb de fenêtres "normales" avant d'entraîner le modèle
HISTORY_MAXLEN = 500                 # nb de points gardés pour le graphique

app = Flask(__name__)

# État partagé (thread de scraping + thread Flask)
state = {
    "history": deque(maxlen=HISTORY_MAXLEN),   # liste de dicts {time, total, errors_401, error_ratio, score, is_anomaly}
    "model_ready": False,
    "last_alert": None,
}

model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
training_buffer = []

# Compteurs Prometheus cumulés -> on calcule les deltas entre 2 scrapes
last_raw = {"total_requests": 0, "login_401": 0}

METRIC_LINE_RE = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)\{([^}]*)\}\s+([0-9.eE+-]+)\s*$')


def parse_prometheus_text(text):
    """
    Parse très simple du format d'exposition Prometheus.
    On extrait :
      - http_requests_total{...,route="/login",status_code="401"}  -> tentatives échouées
      - http_requests_total{...}                                    -> somme totale (toutes routes)
    """
    total_requests = 0
    login_401 = 0

    for line in text.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        m = METRIC_LINE_RE.match(line.strip())
        if not m:
            continue
        metric_name, labels_raw, value = m.groups()
        try:
            value = float(value)
        except ValueError:
            continue

        if metric_name == "http_requests_total":
            total_requests += value
            if 'route="/login"' in labels_raw and 'status_code="401"' in labels_raw:
                login_401 += value

    return total_requests, login_401


def scrape_loop():
    global last_raw
    while True:
        try:
            resp = requests.get(METRICS_URL, timeout=3)
            total_requests, login_401 = parse_prometheus_text(resp.text)

            delta_total = max(total_requests - last_raw["total_requests"], 0)
            delta_401 = max(login_401 - last_raw["login_401"], 0)
            last_raw["total_requests"] = total_requests
            last_raw["login_401"] = login_401

            error_ratio = (delta_401 / delta_total) if delta_total > 0 else 0.0
            features = [delta_total, delta_401, error_ratio]

            score = 0.0
            is_anomaly = False
            detection_method = None

            if not state["model_ready"]:
                training_buffer.append(features)
                if len(training_buffer) >= WARMUP_SAMPLES:
                    model.fit(np.array(training_buffer))
                    state["model_ready"] = True
                    # Volume de référence appris pendant la phase normale, utilisé
                    # comme garde-fou en complément du modèle ML.
                    arr = np.array(training_buffer)
                    state["baseline_total_mean"] = float(arr[:, 0].mean())
                    state["baseline_total_std"] = float(arr[:, 0].std()) or 1.0
            else:
                pred = model.predict([features])[0]          # -1 = anomalie, 1 = normal
                raw_score = model.decision_function([features])[0]
                ml_anomaly = bool(pred == -1)
                score = float(raw_score)

                # --- Garde-fou basé règle (approche hybride IA + règle, comme
                # dans un vrai SOC) : si le volume de requêtes dépasse largement
                # la moyenne + écart-type appris pendant la phase normale, ou si
                # le nombre absolu d'échecs de login est anormalement élevé,
                # on déclenche aussi l'alerte même si le score ML est ambigu.
                baseline_mean = state.get("baseline_total_mean", 3)
                baseline_std = state.get("baseline_total_std", 1)
                volume_threshold = baseline_mean + 4 * baseline_std
                rule_anomaly = (delta_total > max(volume_threshold, 10)) or (delta_401 >= 8)

                is_anomaly = ml_anomaly or rule_anomaly
                detection_method = "IA" if ml_anomaly else ("règle" if rule_anomaly else None)

                if is_anomaly:
                    state["last_alert"] = {
                        "time": datetime.now().strftime("%H:%M:%S"),
                        "message": (
                            f"Pic suspect détecté ({detection_method}) : {int(delta_401)} échecs de login "
                            f"sur {int(delta_total)} requêtes (ratio {error_ratio:.0%})"
                        ),
                    }

            state["history"].append({
                "time": datetime.now().strftime("%H:%M:%S"),
                "total": delta_total,
                "errors_401": delta_401,
                "error_ratio": round(error_ratio, 3),
                "score": round(score, 3),
                "is_anomaly": is_anomaly,
            })

        except Exception as e:
            state["history"].append({
                "time": datetime.now().strftime("%H:%M:%S"),
                "total": 0, "errors_401": 0, "error_ratio": 0,
                "score": 0, "is_anomaly": False, "error": str(e),
            })

        time.sleep(SCRAPE_INTERVAL_SECONDS)


# ---------------------------------------------------------------------------
# Routes web
# ---------------------------------------------------------------------------

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Mini SOC - Détection d'anomalies IA</title>
<meta http-equiv="refresh" content="5">
<style>
  body { font-family: -apple-system, Segoe UI, Arial, sans-serif; background:#0f1115; color:#e6e6e6; margin:0; padding:24px; }
  h1 { font-size: 22px; margin-bottom: 4px; }
  .sub { color:#9aa0a6; margin-bottom:24px; }
  .status { display:inline-block; padding:4px 12px; border-radius:12px; font-size:13px; font-weight:600; }
  .ok { background:#16382a; color:#4ade80; }
  .warming { background:#3a2f14; color:#fbbf24; }
  .alert-box { background:#3a1414; border:1px solid #b91c1c; color:#fca5a5; padding:16px; border-radius:8px; margin-bottom:20px; font-weight:600; }
  table { width:100%; border-collapse: collapse; font-size:13px; }
  th, td { text-align:left; padding:8px 10px; border-bottom:1px solid #2a2d34; }
  th { color:#9aa0a6; font-weight:500; }
  tr.anomaly { background:#2a1414; color:#fca5a5; font-weight:600; }
  .grid { display:grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-bottom: 24px;}
  .card { background:#181b21; border:1px solid #2a2d34; border-radius:10px; padding:16px; }
  .metric { font-size: 28px; font-weight:700; }
  .label { color:#9aa0a6; font-size:12px; }
</style>
</head>
<body>
  <h1>🛡️ Mini SOC — Détection d'anomalies par IA</h1>
  <div class="sub">Service surveillé : user-auth (login) · Modèle : Isolation Forest · Rafraîchissement auto 5s</div>

  {% if not model_ready %}
    <div class="status warming">⏳ Phase d'apprentissage du trafic normal en cours... ({{ buffer_size }}/{{ warmup }})</div>
  {% else %}
    <div class="status ok">✅ Modèle actif — surveillance en temps réel</div>
  {% endif %}

  {% if last_alert %}
  <div class="alert-box">
    🚨 ALERTE [{{ last_alert.time }}] — {{ last_alert.message }}
  </div>
  {% endif %}

  <div class="grid">
    <div class="card">
      <div class="label">Dernier volume de requêtes (fenêtre 5s)</div>
      <div class="metric">{{ last.total if last else '-' }}</div>
    </div>
    <div class="card">
      <div class="label">Échecs de login (401) sur la fenêtre</div>
      <div class="metric">{{ last.errors_401 if last else '-' }}</div>
    </div>
  </div>

  <table>
    <tr><th>Heure</th><th>Requêtes</th><th>Échecs login (401)</th><th>Ratio erreur</th><th>Score IA</th><th>Statut</th></tr>
    {% for row in history %}
    <tr class="{{ 'anomaly' if row.is_anomaly else '' }}">
      <td>{{ row.time }}</td>
      <td>{{ row.total }}</td>
      <td>{{ row.errors_401 }}</td>
      <td>{{ '%.0f'|format(row.error_ratio*100) }}%</td>
      <td>{{ row.score }}</td>
      <td>{{ '🚨 ANOMALIE' if row.is_anomaly else 'normal' }}</td>
    </tr>
    {% endfor %}
  </table>
</body>
</html>
"""


@app.route("/")
def dashboard():
    history = list(state["history"])[::-1][:40]  # plus récent en haut
    last = history[0] if history else None
    return render_template_string(
        DASHBOARD_HTML,
        history=history,
        last=last,
        model_ready=state["model_ready"],
        buffer_size=len(training_buffer),
        warmup=WARMUP_SAMPLES,
        last_alert=state["last_alert"],
    )


@app.route("/api/status")
def api_status():
    return jsonify({
        "model_ready": state["model_ready"],
        "history": list(state["history"]),
        "last_alert": state["last_alert"],
    })


if __name__ == "__main__":
    t = threading.Thread(target=scrape_loop, daemon=True)
    t.start()
    app.run(host="0.0.0.0", port=8500)

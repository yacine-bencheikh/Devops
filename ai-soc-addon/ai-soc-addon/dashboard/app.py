"""
Mini SOC IA — Application complète
------------------------------------
- Moteur de détection d'anomalies (Isolation Forest + règle hybride) sur les
  métriques Prometheus de user-auth
- Authentification simple (admin/admin)
- Dashboard avec graphiques (Chart.js), table d'alertes
- Génération de rapport PDF
- Assistant IA (Gemini si clé API fournie, sinon réponses basées règles)
"""

import os
import re
import time
import threading
import io
from collections import deque
from datetime import datetime
from functools import wraps

import requests
from flask import (
    Flask, jsonify, render_template, request, redirect,
    url_for, session, send_file
)
from sklearn.ensemble import IsolationForest
import numpy as np

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
METRICS_URL = "http://user-auth:3000/metrics"
SCRAPE_INTERVAL_SECONDS = 5
WARMUP_SAMPLES = 10
HISTORY_MAXLEN = 1000

ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "admin")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "").strip()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "mini-soc-dev-secret-key")

state = {
    "history": deque(maxlen=HISTORY_MAXLEN),
    "model_ready": False,
    "last_alert": None,
    "baseline_total_mean": 3,
    "baseline_total_std": 1,
}

model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
training_buffer = []
last_raw = {"total_requests": 0, "login_401": 0, "per_route": {}}

METRIC_LINE_RE = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)\{([^}]*)\}\s+([0-9.eE+-]+)\s*$')
ROUTE_RE = re.compile(r'route="([^"]*)"')
STATUS_RE = re.compile(r'status_code="([^"]*)"')


def parse_prometheus_text(text):
    """
    Retourne :
      - total_requests (somme globale cumulée)
      - login_401 (cumulé, requêtes /login en échec)
      - per_route: dict {route: total_cumulé} pour TOUTES les routes vues
    """
    total_requests = 0
    login_401 = 0
    per_route = {}

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
            route_m = ROUTE_RE.search(labels_raw)
            status_m = STATUS_RE.search(labels_raw)
            route_key = route_m.group(1) if route_m else "unknown"
            per_route[route_key] = per_route.get(route_key, 0) + value
            if route_key == "/login" and status_m and status_m.group(1) == "401":
                login_401 += value

    return total_requests, login_401, per_route


import random

SIMULATED_IP_POOL = [
    "185.220.101.47", "45.155.205.12", "194.26.135.83",
    "103.94.4.21", "91.219.236.18", "176.10.99.200",
]


def classify_threat(delta_total, delta_401, error_ratio, route_diversity, max_route_share):
    """
    Classifie le type de menace selon la signature du trafic, et propose
    une contre-mesure adaptée (simulée — pas d'action réelle sur le réseau).

    ⚠️ L'IP source est SIMULÉE (illustrative) : les métriques Prometheus
    agrégées ne contiennent pas d'adresse IP individuelle. Une vraie
    attribution nécessiterait l'analyse des logs d'accès bruts.
    """
    simulated_ip = random.choice(SIMULATED_IP_POOL)
    ip_note = f"{simulated_ip} (IP simulée à titre illustratif — non issue des logs réels)"

    if error_ratio > 0.5 and delta_401 >= 8:
        return {
            "type": "Brute-force / Credential stuffing",
            "description": (
                f"Volume anormal de tentatives de connexion échouées ({int(delta_401)} échecs "
                f"sur {int(delta_total)} requêtes, {error_ratio:.0%} d'échec) concentré sur /login. "
                "Signature typique d'une attaque par dictionnaire ou credential stuffing."
            ),
            "countermeasure": "Blocage temporaire de la source (simulation) + recommandation MFA",
            "severity": "CRITIQUE",
            "source_ip": ip_note,
        }
    if route_diversity >= 5:
        return {
            "type": "Scan de reconnaissance",
            "description": (
                f"{route_diversity} endpoints distincts sollicités en rafale sur une courte fenêtre "
                f"({int(delta_total)} requêtes). Signature typique d'une énumération de routes "
                "(recherche de pages d'administration, fichiers de config exposés, etc.)."
            ),
            "countermeasure": "Renforcement de la surveillance + rate-limiting sur routes sensibles (simulation)",
            "severity": "ÉLEVÉE",
            "source_ip": ip_note,
        }
    if max_route_share > 0.85 and delta_total > 30:
        return {
            "type": "Déni de service (DDoS volumétrique)",
            "description": (
                f"Pic de volume extrême ({int(delta_total)} requêtes/fenêtre) concentré à "
                f"{max_route_share:.0%} sur une seule route, avec un faible taux d'erreur. "
                "Signature typique d'une attaque par saturation (flood)."
            ),
            "countermeasure": "Activation du rate-limiting global + mise en cache renforcée (simulation)",
            "severity": "CRITIQUE",
            "source_ip": ip_note,
        }
    return {
        "type": "Anomalie non classifiée",
        "description": f"Écart statistique détecté ({int(delta_total)} requêtes, {error_ratio:.0%} d'échec) ne correspondant à aucune signature connue.",
        "countermeasure": "Investigation manuelle recommandée",
        "severity": "MOYENNE",
        "source_ip": ip_note,
    }


def scrape_loop():
    global last_raw
    while True:
        try:
            resp = requests.get(METRICS_URL, timeout=3)
            total_requests, login_401, per_route = parse_prometheus_text(resp.text)

            delta_total = max(total_requests - last_raw["total_requests"], 0)
            delta_401 = max(login_401 - last_raw["login_401"], 0)

            # Deltas par route (pour diversité + part max)
            route_deltas = {}
            for route, cum in per_route.items():
                prev = last_raw["per_route"].get(route, cum)
                d = max(cum - prev, 0)
                if d > 0:
                    route_deltas[route] = d
            route_diversity = len(route_deltas)
            max_route_share = (max(route_deltas.values()) / delta_total) if delta_total > 0 and route_deltas else 0

            last_raw["total_requests"] = total_requests
            last_raw["login_401"] = login_401
            last_raw["per_route"] = per_route

            error_ratio = (delta_401 / delta_total) if delta_total > 0 else 0.0
            features = [delta_total, delta_401, error_ratio]

            score = 0.0
            is_anomaly = False
            threat = None

            if not state["model_ready"]:
                training_buffer.append(features)
                if len(training_buffer) >= WARMUP_SAMPLES:
                    model.fit(np.array(training_buffer))
                    state["model_ready"] = True
                    arr = np.array(training_buffer)
                    state["baseline_total_mean"] = float(arr[:, 0].mean())
                    state["baseline_total_std"] = float(arr[:, 0].std()) or 1.0
            else:
                pred = model.predict([features])[0]
                raw_score = model.decision_function([features])[0]
                ml_anomaly = bool(pred == -1)
                score = float(raw_score)

                baseline_mean = state.get("baseline_total_mean", 3)
                baseline_std = state.get("baseline_total_std", 1)
                volume_threshold = baseline_mean + 4 * baseline_std
                rule_anomaly = (delta_total > max(volume_threshold, 10)) or (delta_401 >= 8) or (route_diversity >= 5)

                is_anomaly = ml_anomaly or rule_anomaly

                if is_anomaly:
                    threat = classify_threat(delta_total, delta_401, error_ratio, route_diversity, max_route_share)
                    state["last_alert"] = {
                        "time": datetime.now().strftime("%H:%M:%S"),
                        "message": f"{threat['type']} — {threat['description']}",
                        "threat": threat,
                    }

            state["history"].append({
                "time": datetime.now().strftime("%H:%M:%S"),
                "total": delta_total,
                "errors_401": delta_401,
                "error_ratio": round(error_ratio, 3),
                "route_diversity": route_diversity,
                "score": round(score, 3),
                "is_anomaly": is_anomaly,
                "threat": threat,
            })

        except Exception as e:
            state["history"].append({
                "time": datetime.now().strftime("%H:%M:%S"),
                "total": 0, "errors_401": 0, "error_ratio": 0, "route_diversity": 0,
                "score": 0, "is_anomaly": False, "threat": None, "error": str(e),
            })

        time.sleep(SCRAPE_INTERVAL_SECONDS)


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        if request.form.get("username") == ADMIN_USER and request.form.get("password") == ADMIN_PASS:
            session["logged_in"] = True
            return redirect(url_for("dashboard"))
        error = "Identifiant ou mot de passe incorrect."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
@app.route("/")
@login_required
def dashboard():
    history = list(state["history"])[::-1][:60]
    last = history[0] if history else None
    anomaly_count = sum(1 for h in state["history"] if h.get("is_anomaly"))
    import json as _json
    return render_template(
        "dashboard.html",
        history=history,
        history_json=_json.dumps(history),
        last=last,
        model_ready=state["model_ready"],
        last_alert=state["last_alert"],
        anomaly_count=anomaly_count,
        active="dashboard",
    )


@app.route("/alertes")
@login_required
def alerts_page():
    alerts = [h for h in state["history"] if h.get("is_anomaly")][::-1]
    return render_template("alerts.html", alerts=alerts, active="alerts")


@app.route("/assistant")
@login_required
def assistant_page():
    return render_template("assistant.html", ai_enabled=bool(GEMINI_API_KEY), active="assistant")


@app.route("/api/status")
@login_required
def api_status():
    return jsonify({
        "model_ready": state["model_ready"],
        "history": list(state["history"]),
        "last_alert": state["last_alert"],
    })


# ---------------------------------------------------------------------------
# Assistant IA (Gemini si clé dispo, sinon règles)
# ---------------------------------------------------------------------------
def build_context_summary():
    history = list(state["history"])[-30:]
    anomalies_recent = [h for h in history if h.get("is_anomaly")]
    anomalies_total = [h for h in state["history"] if h.get("is_anomaly")]
    last = history[-1] if history else None
    avg_total = round(sum(h["total"] for h in history) / len(history), 1) if history else 0
    avg_errors = round(sum(h["errors_401"] for h in history) / len(history), 1) if history else 0
    max_total = max((h["total"] for h in history), default=0)
    return {
        "model_ready": state["model_ready"],
        "nb_points_recents": len(history),
        "nb_anomalies_recentes": len(anomalies_recent),
        "nb_anomalies_total": len(anomalies_total),
        "derniere_mesure": last,
        "derniere_alerte": state["last_alert"],
        "moyenne_requetes": avg_total,
        "moyenne_echecs": avg_errors,
        "pic_max_requetes": max_total,
    }


def rule_based_reply(message, ctx):
    msg = message.lower().strip()

    def has(*words):
        return any(w in msg for w in words)

    # Salutations
    if has("bonjour", "salut", "hello", "coucou", "bonsoir"):
        return (
            "Bonjour 👋 Je suis l'assistant du SOC. Je peux te résumer la situation, "
            "détailler les dernières alertes, expliquer le fonctionnement du système, "
            "ou donner des recommandations de sécurité. Que veux-tu savoir ?"
        )

    # Résumé / situation générale
    if has("résume", "resume", "situation", "état", "etat global", "rapport rapide"):
        if ctx["nb_anomalies_recentes"] > 0:
            return (
                f"⚠️ Situation actuelle : sur les {ctx['nb_points_recents']} dernières mesures (≈{ctx['nb_points_recents']*5}s), "
                f"j'ai compté {ctx['nb_anomalies_recentes']} anomalie(s). Trafic moyen : {ctx['moyenne_requetes']} requêtes/fenêtre "
                f"(pic à {ctx['pic_max_requetes']}). Dernière alerte : {ctx['derniere_alerte']['message'] if ctx['derniere_alerte'] else 'aucune'}."
            )
        return (
            f"✅ Tout est calme. Trafic moyen observé : {ctx['moyenne_requetes']} requêtes par fenêtre de 5s, "
            f"avec {ctx['moyenne_echecs']} échecs de login en moyenne — c'est dans la norme. "
            f"Total d'anomalies enregistrées depuis le démarrage : {ctx['nb_anomalies_total']}."
        )

    # Que s'est-il passé / attaque
    if has("que s'est", "passé", "attaque", "incident", "brute", "menace"):
        alerte = ctx["derniere_alerte"]
        if alerte:
            threat = alerte.get("threat")
            if threat:
                return (
                    f"🚨 Dernière menace détectée à {alerte['time']} : {threat['type']} (sévérité {threat['severity']}). "
                    f"{threat['description']} Source : {threat['source_ip']}. "
                    f"Contre-mesure appliquée (simulée) : {threat['countermeasure']}."
                )
            return f"🚨 Dernier événement suspect détecté à {alerte['time']} : {alerte['message']}."
        return "Aucun événement suspect n'a été enregistré pour l'instant — le système n'a rien détecté d'anormal."

    # Combien d'anomalies / statistiques
    if has("combien", "nombre d'anomalie", "statistique", "stats"):
        return (
            f"Depuis le démarrage de la surveillance : {ctx['nb_anomalies_total']} anomalie(s) détectée(s) au total. "
            f"Sur la fenêtre récente : {ctx['nb_anomalies_recentes']} anomalie(s), avec un pic de {ctx['pic_max_requetes']} requêtes "
            "sur une fenêtre de 5 secondes."
        )

    # Comment ça marche
    if has("comment") and has("marche", "fonctionne", "détection", "detection"):
        return (
            "Je surveille les métriques Prometheus exposées par le service user-auth toutes les 5 secondes "
            "(volume de requêtes, échecs de login). Un modèle Isolation Forest (apprentissage non supervisé) "
            "apprend le comportement normal du trafic, puis signale tout écart statistique significatif. "
            "Une règle complémentaire sur le volume agit en filet de sécurité pour ne rien laisser passer."
        )

    # Isolation Forest / IA
    if has("isolation forest", "modèle", "modele", "ia", "intelligence artificielle", "machine learning", "algorithme"):
        return (
            "J'utilise l'algorithme Isolation Forest : il isole les points de données qui s'écartent du comportement "
            "normal en les séparant plus rapidement que la majorité (moins de divisions nécessaires = plus suspect). "
            "C'est un algorithme non supervisé, donc il n'a pas besoin d'exemples d'attaques pour apprendre à les repérer."
        )

    # Recommandations
    if has("recommand", "que faire", "conseil", "protéger", "proteger", "sécuriser", "securiser"):
        return (
            "Mes recommandations actuelles : (1) bloquer temporairement une IP après plusieurs échecs de login "
            "consécutifs (rate limiting), (2) activer l'authentification à deux facteurs sur les comptes sensibles, "
            "(3) journaliser les IP sources pour investigation, (4) surveiller aussi les autres routes sensibles "
            "comme /api/auth/refresh."
        )

    # Aide / capacités
    if has("aide", "help", "que peux-tu", "capacité"):
        return (
            "Je peux : résumer la situation de sécurité actuelle, détailler la dernière alerte, "
            "donner des statistiques sur les anomalies, expliquer comment fonctionne la détection, "
            "ou donner des recommandations de sécurité. Essaie par exemple : 'combien d'anomalies ?' "
            "ou 'comment fonctionne la détection ?'."
        )

    # Merci / au revoir
    if has("merci", "au revoir", "bye"):
        return "Avec plaisir ! Je reste actif si tu as d'autres questions sur la sécurité du système. 🛡️"

    # Réponse par défaut, mais toujours contextuelle et utile (pas un message figé)
    return (
        f"Je n'ai pas reconnu de question précise, mais voici l'état actuel : "
        f"{ctx['nb_anomalies_recentes']} anomalie(s) récente(s), trafic moyen de {ctx['moyenne_requetes']} requêtes/fenêtre. "
        "Tu peux me demander : 'résume la situation', 'que s'est-il passé ?', 'combien d'anomalies ?', "
        "'comment fonctionne la détection ?' ou 'quelles recommandations ?'."
    )


def gemini_reply(message, ctx):
    url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"gemini-2.0-flash:generateContent?key={GEMINI_API_KEY}"
    )
    system_context = (
        "Tu es l'assistant IA d'un mini SOC (Security Operations Center) pour un projet "
        "académique DevSecOps. Tu réponds en français, de façon concise et claire (3-5 phrases max), "
        "comme un analyste sécurité junior qui explique des éléments à un étudiant. "
        f"Contexte technique actuel (JSON) : {ctx}"
    )
    payload = {
        "contents": [{"parts": [{"text": f"{system_context}\n\nQuestion de l'utilisateur : {message}"}]}]
    }
    r = requests.post(url, json=payload, timeout=15)
    r.raise_for_status()
    data = r.json()
    return data["candidates"][0]["content"]["parts"][0]["text"]


@app.route("/api/assistant", methods=["POST"])
@login_required
def api_assistant():
    message = request.json.get("message", "")
    ctx = build_context_summary()

    if GEMINI_API_KEY:
        try:
            reply = gemini_reply(message, ctx)
        except requests.exceptions.HTTPError as e:
            status = e.response.status_code if e.response is not None else None
            print(f"[assistant] Erreur HTTP Gemini ({status}): {e.response.text if e.response is not None else e}")
            if status == 429:
                reply = (
                    "⏳ Le quota gratuit de l'API Gemini est temporairement atteint "
                    "(limite de requêtes par minute). Réessaie dans environ une minute. "
                    f"En attendant : {rule_based_reply(message, ctx)}"
                )
            else:
                reply = f"(Erreur appel IA, repli sur mode règles) {rule_based_reply(message, ctx)}"
        except Exception as e:
            print(f"[assistant] Erreur appel Gemini: {repr(e)}")
            reply = f"(Erreur appel IA, repli sur mode règles) {rule_based_reply(message, ctx)}"
    else:
        reply = rule_based_reply(message, ctx)

    return jsonify({"reply": reply})


# ---------------------------------------------------------------------------
# Rapport PDF
# ---------------------------------------------------------------------------
@app.route("/rapport.pdf")
@login_required
def rapport_pdf():
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleX", parent=styles["Title"], textColor=colors.HexColor("#7a1f2b"))
    h2_style = ParagraphStyle("H2X", parent=styles["Heading2"], textColor=colors.HexColor("#b8293a"))
    normal = styles["Normal"]

    elements = []
    elements.append(Paragraph("Rapport de Sécurité — AuraSOC", title_style))
    elements.append(Paragraph(f"Généré le {datetime.now().strftime('%d/%m/%Y à %H:%M:%S')}", normal))
    elements.append(Spacer(1, 16))

    elements.append(Paragraph("1. Résumé exécutif", h2_style))
    anomaly_count = sum(1 for h in state["history"] if h.get("is_anomaly"))
    total_points = len(state["history"])
    summary_text = (
        f"Le système a analysé {total_points} fenêtres de surveillance (5 secondes chacune) "
        f"sur le service user-auth. {anomaly_count} anomalie(s) ont été détectées par le "
        f"moteur hybride (Isolation Forest + règle de volume)."
    )
    elements.append(Paragraph(summary_text, normal))
    elements.append(Spacer(1, 16))

    elements.append(Paragraph("2. Méthodologie", h2_style))
    elements.append(Paragraph(
        "Les métriques Prometheus exposées par le microservice user-auth (volume de requêtes, "
        "taux d'échec de connexion) sont collectées toutes les 5 secondes. Un modèle d'apprentissage "
        "non supervisé (Isolation Forest) apprend le comportement normal du trafic, puis évalue chaque "
        "nouvelle fenêtre. Une règle complémentaire basée sur le volume agit comme filet de sécurité.",
        normal
    ))
    elements.append(Spacer(1, 16))

    elements.append(Paragraph("3. Alertes détectées", h2_style))
    anomalies = [h for h in state["history"] if h.get("is_anomaly")][-20:]
    if anomalies:
        data = [["Heure", "Type de menace", "Sévérité", "Requêtes", "Échecs", "Source (simulée)"]]
        for a in anomalies:
            t = a.get("threat") or {}
            data.append([
                a["time"], t.get("type", "-"), t.get("severity", "-"),
                str(a["total"]), str(a["errors_401"]),
                t.get("source_ip", "-").split(" ")[0] if t.get("source_ip") else "-",
            ])
        table = Table(data, hAlign="LEFT", colWidths=[1.6*cm, 5*cm, 1.8*cm, 1.6*cm, 1.6*cm, 2.8*cm])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#7a1f2b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f0f0")]),
        ]))
        elements.append(table)
        elements.append(Spacer(1, 10))
        elements.append(Paragraph(
            "⚠️ Note méthodologique : les adresses IP affichées sont <b>simulées à titre illustratif</b>. "
            "Les métriques Prometheus agrégées utilisées par ce système ne contiennent pas d'identifiant "
            "réseau individuel ; une attribution réelle nécessiterait l'analyse des journaux d'accès bruts.",
            ParagraphStyle("NoteX", parent=normal, fontSize=8, textColor=colors.HexColor("#777777"))
        ))
    else:
        elements.append(Paragraph("Aucune anomalie détectée durant la période de surveillance.", normal))

    elements.append(Spacer(1, 18))
    elements.append(Paragraph("4. Explication des types de menaces détectables", h2_style))
    threat_explanations = [
        ("Brute-force / Credential stuffing",
         "Tentatives répétées de connexion avec des mots de passe différents sur un même compte. "
         "Détecté via un taux d'échec de login anormalement élevé concentré sur une courte période."),
        ("Scan de reconnaissance",
         "Sondage rapide de nombreux endpoints différents (souvent à la recherche de routes "
         "d'administration ou de fichiers exposés). Détecté via une forte diversité de routes sollicitées."),
        ("Déni de service (DDoS volumétrique)",
         "Flot massif de requêtes visant à saturer le service. Détecté via un pic de volume extrême "
         "concentré sur une seule route, avec un faible taux d'erreur."),
    ]
    for name, desc in threat_explanations:
        elements.append(Paragraph(f"<b>{name}</b> — {desc}", normal))
        elements.append(Spacer(1, 6))

    elements.append(Spacer(1, 12))
    elements.append(Paragraph("5. Recommandations", h2_style))
    elements.append(Paragraph(
        "En cas de détection répétée de pics d'échecs de connexion, il est recommandé de : "
        "(1) mettre en place un blocage temporaire des IP sources après N tentatives échouées, "
        "(2) activer une authentification multi-facteurs sur les comptes sensibles, "
        "(3) journaliser les adresses IP sources pour investigation.",
        normal
    ))

    doc.build(elements)
    buf.seek(0)
    return send_file(buf, mimetype="application/pdf", download_name="rapport_securite_soc.pdf")


if __name__ == "__main__":
    if GEMINI_API_KEY:
        print(f"[startup] Clé Gemini détectée (longueur {len(GEMINI_API_KEY)}, débute par '{GEMINI_API_KEY[:6]}...')")
    else:
        print("[startup] Aucune clé Gemini détectée — mode hors-ligne (règles)")
    t = threading.Thread(target=scrape_loop, daemon=True)
    t.start()
    app.run(host="0.0.0.0", port=8500)

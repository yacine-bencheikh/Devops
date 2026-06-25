# Guide d'exécution — Mini SOC IA v3 (dashboard complet)

## Nouveautés de cette version

- 🔐 Page de connexion (login: `admin` / mot de passe: `admin`)
- 📊 Dashboard avec graphiques temps réel (Chart.js) + cartes KPI
- 🚨 Page dédiée "Alertes" listant tout l'historique des anomalies
- 📄 Génération de rapport PDF en un clic
- 🤖 Assistant IA conversationnel (connecté à Gemini si tu as une clé API)

## 1. Remplacer les fichiers

1. Supprime l'ancien dossier `ai-soc-addon` à la racine de `Devops-main`
2. Mets le nouveau dossier `ai-soc-addon` à sa place (au même endroit)
3. Vérifie que `docker-compose.ai-soc.yml` est bien à la racine de `Devops-main`
   (à côté de `docker-compose.yml`) — sinon recopie-le depuis `ai-soc-addon/`

## 2. Configurer la clé Gemini (optionnel mais recommandé)

Si tu as récupéré une clé sur https://aistudio.google.com/app/apikey :

1. Crée un fichier `.env` à la racine de `Devops-main` s'il n'existe pas déjà
   (normalement tu en as déjà un, copié depuis `.env.development`)
2. Ajoute cette ligne à la fin de ce fichier `.env` :

```
GEMINI_API_KEY=colle_ta_cle_ici
```

Si tu ne mets rien, l'assistant fonctionnera en "mode hors-ligne" avec des
réponses basées sur des règles simples — ça fonctionne aussi, juste moins riche.

## 3. Lancer

Depuis la racine de `Devops-main` (PowerShell) :

```powershell
docker compose -f docker-compose.yml -f docker-compose.dev.yml -f docker-compose.ai-soc.yml down
docker compose -f docker-compose.yml -f docker-compose.dev.yml -f docker-compose.ai-soc.yml up -d --build
```

## 4. Accéder au dashboard

Ouvre : **http://localhost:8500**

- Identifiant : `admin`
- Mot de passe : `admin`

Une fois connecté tu as accès à :
- **Dashboard** : vue d'ensemble avec graphiques temps réel
- **Alertes** : liste complète des anomalies détectées
- **Assistant IA** : pose des questions ("résume la situation", "que s'est-il passé ?")
- **Rapport PDF** : clique pour télécharger un rapport de sécurité généré automatiquement

## 5. Déclencher une attaque pour la démo

```powershell
docker compose -f docker-compose.yml -f docker-compose.dev.yml -f docker-compose.ai-soc.yml restart attack-simulator
```

Attends ~60-70 secondes, rafraîchis le dashboard : tu dois voir le pic et les
alertes rouges apparaître, le compteur "Anomalies détectées" s'incrémenter,
et la page Alertes se remplir.

## 6. Ce qu'il faut savoir expliquer à l'oral

- **Détection** : Isolation Forest (ML non supervisé) + règle de sécurité
  complémentaire sur les métriques Prometheus déjà exposées par `user-auth`
- **Interface** : dashboard de type SOC professionnel (inspiré des plateformes
  comme Prophet Security), avec authentification, visualisation temps réel,
  et génération de rapports
- **Assistant IA** : agent conversationnel connecté à un LLM (Gemini), capable
  d'interroger le contexte de sécurité en cours et de répondre en langage naturel
  — illustre la convergence DevSecOps + SOC + IA générative
- **Limites à mentionner** : authentification simplifiée pour la démo (pas de
  vraie gestion utilisateur), modèle entraîné sur peu de données, pas de
  remédiation automatique (blocage IP) — pistes d'évolution futures

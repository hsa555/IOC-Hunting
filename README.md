```
      .·¨'`;        ,.·´¨;\                ,. -,                    ,.,   '         .----------. 
     ';   ;'\       ';   ;::\         ,.·'´,    ,'\                 ;´   '· .,         /          /  
     ;   ;::'\      ,'   ;::';    ,·'´ .·´'´-·'´::::\'             .´  .-,    ';\        /   ______.'   
     ;  ;::_';,. ,.'   ;:::';°  ;    ';:::\::\::;:'             /   /:\:';   ;:'\'       /   /_          
   .'     ,. -·~-·,   ;:::'; '  \·.    `·;:'-·'´              ,'  ,'::::'\';  ;::';      /      '''--.    
   ';   ;'\::::::::;  '/::::;     \:`·.   '`·,  '          ,.-·'  '·~^*'´¨,  ';::;     '___          `.  
    ;  ';:;\;::-··;  ;::::;        `·:'`·,   \'           ':,  ,·:²*´¨¯'`;  ;::';         `'.         | 
    ':,.·´\;'    ;' ,' :::/  '        ,.'-:;'  ,·\          ,'  / \::::::::';  ;::';            )        | 
     \:::::\    \·.'::::;      ,·'´     ,.·´:::'\        ,' ,'::::\·²*'´¨¯':,'\:;    ......-'        /  
       \;:·´     \:\::';        \`*'´\::::::::;·''       \`¨\:::/          \::\'    \          _..'`   
                  `·\;'          \::::\:;:·´             '\::\;'            '\;'  '     '------'''        
                     '             '`*'´'                   `¨'                       
```

# IOC Hunting

**Made by hsa5**

Outil de threat hunting en ligne de commande qui corrèle automatiquement plusieurs sources OSINT pour analyser des **IPs, URLs et hashes** malveillants. Toutes les sources utilisées sont gratuites.

---

## Fonctionnalités

- **Deux modes d'analyse** :
  - **Mode IP / URL / Domaine** : corrélation multi-sources (AbuseIPDB · VirusTotal · Shodan · Censys · URLhaus · GreyNoise)
  - **Mode Hash** : analyse de fichiers via VirusTotal + URLhaus + MalwareBazaar (MD5, SHA1, SHA256)
- **Auto-détection** du type de cible passé en argument (IPv4, IPv6, URL, domaine ou hash)
- **Score de menace agrégé** (0–100) avec niveau FAIBLE / MODÉRÉ / ÉLEVÉ / CRITIQUE
- **Analyse VirusTotal approfondie** :
  - Détections moteurs AV
  - Crowdsourced YARA Rules
  - Crowdsourced Sigma Rules
  - Crowdsourced IDS Rules
  - Dynamic Analysis — Sandbox Verdicts
  - Crowdsourced Context
  - Communicating Files & Referrer Files (mode IP)
- **Ports ouverts et services** via Shodan (fallback InternetDB sans clé) et Censys
- **GreyNoise** : détecte si une IP scanne activement internet — sans clé requise (plan communautaire)
- **MalwareBazaar** : famille malware, tags comportementaux (`stealer`, `loader`, `ransomware`...), méthode de livraison et vendor intel sur les hashes — même clé qu'URLhaus
- **Barre de progression** en bas du terminal lors de l'analyse de listes de cibles
- **Hachage local de fichiers** : calcule le SHA256 de fichiers/répertoires locaux, puis les interroge
- **Scan de répertoire** : si un répertoire est fourni à la place d'un fichier, tous les fichiers sont traités
- **Cache des résultats** : évite de reconsommer du quota API — durée configurable via `setup.py` (24h par défaut), purgé automatiquement au lancement. Option `--nocache` pour forcer des requêtes fraîches
- **Google Dorks** (`--dorks` / prompt interactif) : recherche Google via SerpAPI des mentions d'une IP sur le web ouvert (forums, listes GitHub, rapports CTI) — résultats triés par pertinence CTI (botnet, malware, phishing, APT…), exclusion automatique des scanners/blacklists connus
- **Interface web locale** (`--web`) : UI dark-theme dans le navigateur, bind uniquement sur 127.0.0.1, protection CSRF, une carte de résultat par cible, nav cliquable pour multi-cibles, téléchargement JSON
- **Chiffrement des clés API** : Fernet/AES-128-CBC + PBKDF2-HMAC-SHA256 (480 000 itérations)
- **Export JSON et CSV** : `--export rapport.json` ou `--export rapport.csv` (détecté à l'extension)
- **Mode silencieux** : `--quiet` supprime toute sortie, code retour `1` si score ≥ seuil (`--threshold N`, défaut 40) — idéal pour les scripts et pipelines
- **Lecture stdin** : `--file -` lit les cibles depuis stdin (`cat targets.txt | python3 main.py --file -`)
- **Déduplication automatique** des cibles — les doublons dans un fichier ne sont traités qu'une fois
- **Mise à jour automatique** : `update.py` vérifie et applique les mises à jour depuis GitHub, avec rollback possible
- **Ctrl+C propre** : message d'arrêt au lieu d'une traceback
- Scripts standalone par source pour un usage indépendant

---

## Installation

```bash
cd IOCHunting
pip install -r requirements.txt
python3 setup.py
```

`setup.py` configure les clés API et la durée du cache (24h par défaut). Au premier lancement, il propose de **chiffrer ou non** les clés (Fernet/AES — optionnel). Le chiffrement peut être activé ou désactivé à tout moment depuis le menu. À relancer pour modifier une valeur.

> **Passphrase oubliée ?** Lance `python3 setup.py` et choisis **Reset complet** (accessible sans passphrase). Toutes les clés chiffrées sont supprimées et une nouvelle configuration repart de zéro.

---

## Sources et clés API (toutes gratuites)

| Source | Utilité | Clé requise | Lien |
|--------|---------|-------------|------|
| AbuseIPDB | Score d'abus, rapports communautaires | Oui | https://www.abuseipdb.com/account/api |
| VirusTotal | Scan multi-AV, YARA, Sigma, IDS, Sandbox | Oui | https://www.virustotal.com/gui/my-apikey |
| Shodan | Ports ouverts, CVEs, services | Optionnelle* | https://account.shodan.io/ |
| Censys | Ports ouverts, services détaillés | Oui | https://app.censys.io/user/tokens |
| URLhaus | URLs malveillantes, hashes malwares | Oui | https://auth.abuse.ch/ |
| SerpAPI | Google Dorks — mentions web (forums, GitHub, rapports CTI) | Optionnelle | https://serpapi.com/ |
| GreyNoise | Scan internet — scanner légitime, malveillant ou trafic ciblé | Aucune* | https://www.greynoise.io/ |
| MalwareBazaar | Famille, tags, vendor intel sur les hashes | Même clé qu'URLhaus | https://auth.abuse.ch/ |

*Sans clé Shodan, l'outil utilise automatiquement **Shodan InternetDB** (gratuit, sans clé, ports/vulns/hostnames).
*GreyNoise fonctionne sans clé via l'endpoint communautaire public.

---

## Usage

### Analyse principale (corrélation multi-sources)

```bash
# Analyser une IP — auto-détectée
python3 main.py 1.2.3.4

# Analyser une URL — auto-détectée
python3 main.py https://malicious.example.com/payload

# Analyser un hash — auto-détecté (MD5 / SHA1 / SHA256)
python3 main.py d41d8cd98f00b204e9800998ecf8427e

# Analyser plusieurs cibles (mélange IP/URL accepté)
python3 main.py 1.2.3.4 5.6.7.8 https://example.com

# Analyser un domaine — auto-détecté
python3 main.py evil.com

# Depuis un fichier texte (une cible par ligne, # = commentaire)
python3 main.py --file targets.txt

# Depuis stdin
cat targets.txt | python3 main.py --file -

# Forcer le mode hash
python3 main.py --type hash abc123...

# Forcer le mode IP/URL
python3 main.py --type ip 1.2.3.4

# Filtrer les fichiers VirusTotal par année
python3 main.py 1.2.3.4 --year 2025
python3 main.py 1.2.3.4 --year 2024,2025

# Exporter le rapport en JSON ou CSV
python3 main.py 1.2.3.4 --export rapport.json
python3 main.py 1.2.3.4 --export rapport.csv

# Mode silencieux (code retour 1 si score ≥ 40)
python3 main.py --quiet 1.2.3.4
python3 main.py --quiet --threshold 70 1.2.3.4

# Sortie JSON brute (machine-readable)
python3 main.py 1.2.3.4 --json

# Forcer les requêtes API (ignore le cache)
python3 main.py 1.2.3.4 --nocache

# Afficher aussi les payloads URLhaus offline (online-only par défaut)
python3 main.py 1.2.3.4 --offline

# Lancer l'interface web locale
python3 main.py --web

# Google Dorks (standalone)
python3 modules/googledorks_lookup.py 1.2.3.4
```

### Interface web locale (`--web`)

Lance un serveur Flask **uniquement accessible depuis la machine locale** (127.0.0.1). Ouvre ensuite `http://127.0.0.1:<port>` dans le navigateur.

```bash
python3 main.py --web
# → Propose le port (5000 par défaut, configurable via setup.py)
# → Démarre le serveur et affiche l'URL
```

- Bind sur 127.0.0.1 uniquement — jamais exposé sur le réseau
- Protection CSRF sur chaque soumission (token généré au lancement)
- Résultats colorés (ANSI → HTML), identiques au terminal
- **Multi-cibles** : textarea multi-lignes (une cible par ligne) ou chargement d'un fichier `.txt`
- Une carte de résultat par cible, avec nav cliquable pour scroller directement à une carte
- Bouton `↓ JSON` pour télécharger tous les résultats au format JSON
- Bouton scroll-to-top fixe en bas à gauche (apparaît après 300px de scroll)
- Historique des 10 dernières analyses dans `localStorage`
- Options "Ignorer le cache" et filtre année disponibles
- Validation : erreur si plusieurs cibles sur une même ligne (séparées par espace)

> **Note** : nécessite Flask (`pip install flask` ou `pip install -r requirements.txt`). Ne jamais lancer en root sur un serveur partagé.

### Google Dorks (mentions web)

Lance une recherche Google via **SerpAPI** pour trouver les mentions de l'IP sur le web ouvert : forums, listes GitHub, rapports CTI, write-ups, etc.

- **Mode interactif** : au début d'une session multi-cibles, le script demande une fois `Lancer Google Dorks ?`. Si `o`, les Dorks tournent automatiquement après chaque analyse sans redemander.
- **Standalone** :

```bash
python3 modules/googledorks_lookup.py 1.2.3.4
python3 modules/googledorks_lookup.py 1.2.3.4 --num 20
```

- **Clé SerpAPI** : plan gratuit = **100 requêtes/mois** (3 req par analyse : page 1 + page 2 + sous-réseau /24). Configure via `python setup.py`.
- **Filtrage** : les scanners d'IP (ipinfo, AbuseIPDB, Shodan…) et blacklists sont exclus automatiquement. Les résultats contenant des mots-clés CTI (botnet, malware, phishing, APT…) remontent en premier.

### Hachage de fichiers locaux (mode hash)

Le mode hash peut analyser directement des **fichiers locaux** — il calcule leur SHA256, puis interroge VirusTotal et URLhaus.

```bash
# Via le menu interactif → choix "2 — Analyser un hash" → option "2 — Hasher un fichier/répertoire"
python3 main.py --type hash
```

Si un **répertoire** est fourni, tous les fichiers qu'il contient sont hashés et analysés.

### Menu interactif (sans argument)

```bash
python3 main.py
```

Affiche un menu principal avec trois modes :
- **1 — IP / URL** : saisie directe, fichier ou répertoire
- **2 — Hash** : saisie de hash ou hachage de fichiers
- **w — Interface web** : lance le serveur local dans le navigateur
- **r — Retour** disponible dans chaque sous-menu pour revenir au menu principal

### Configuration des clés API

```bash
# Configuration initiale (à faire une seule fois)
python3 setup.py
```

Les clés sont stockées chiffrées dans `~/.config/ioc_hunting/keys.json`.

La passphrase de déchiffrement peut être fournie de trois façons :

#### Option 1 — Prompt interactif (recommandé)

```bash
python3 main.py 1.2.3.4
```

Demandée à chaque lancement, jamais stockée.

✔ Aucune passphrase exposée.  
✘ À saisir à chaque nouveau lancement.

#### Option 2 — Variable inline (pratique, risque limité)

```bash
THREAT_HUNTING_PASSPHRASE='passphrase' python3 main.py 1.2.3.4
```

✔ Pas besoin de saisie dans la même session.  
✘ Visible dans `/proc/<pid>/environ` — risque négligeable en local.

#### Option 3 — Variable exportée (le plus pratique)

```bash
export THREAT_HUNTING_PASSPHRASE='passphrase'
python3 main.py 1.2.3.4
python3 main.py 5.6.7.8   # pas besoin de la remettre
```

✔ Aucune saisie répétée.  
✘ Héritée par tous les process du terminal — à éviter sur serveur partagé.

---

## Modes de détection automatique (CLI)

Quand des cibles sont passées en argument, `main.py` les identifie automatiquement :

| Format | Détection |
|--------|-----------|
| `1.2.3.4` | IPv4 → AbuseIPDB · VT · Shodan · Censys · URLhaus · GreyNoise |
| `2001:db8::1` | IPv6 → idem |
| `evil.com` | Domaine → VT + URLhaus |
| `https://...` | URL → VT + URLhaus + AbuseIPDB (sur l'IP du host si applicable) |
| 32 hex chars (MD5) | Hash → VT + URLhaus |
| 40 hex chars (SHA1) | Hash → VT + URLhaus |
| 64 hex chars (SHA256) | Hash → VT + URLhaus |

Si toutes les cibles sont des hashes, le mode hash est activé automatiquement. Sinon, le mode IP/URL/Domaine est utilisé.

---

## Scripts standalone (modules/)

Chaque source dispose d'un script indépendant utilisable séparément :

```bash
python3 modules/abuseipdb_lookup.py 1.2.3.4
python3 modules/virustotal_lookup.py 1.2.3.4
python3 modules/virustotal_lookup.py https://example.com --full
python3 modules/virustotal_lookup.py d41d8cd98f00b204e9800998ecf8427e
python3 modules/shodan_lookup.py 1.2.3.4
python3 modules/censys_lookup.py 1.2.3.4
python3 modules/urlhaus_lookup.py https://malicious.example.com
```

Tous supportent : `--file`, `--json`, `--export`, `--key`.  
`virustotal_lookup.py` supporte en plus `--full` pour les relations (communicating files, etc.).

---

## Structure du projet

```
IOC Hunting/
├── main.py               ← point d'entrée principal (corrélation + hash)
├── setup.py              ← configuration et chiffrement des clés API
├── update.py             ← mise à jour automatique depuis GitHub (avec rollback)
├── requirements.txt      ← dépendances Python (pip install -r requirements.txt)
├── README.md
├── .internal/
│   └── config_loader.py  ← chiffrement Fernet, lecture/écriture des clés
└── modules/
    ├── abuseipdb_lookup.py     ← AbuseIPDB standalone
    ├── censys_lookup.py        ← Censys standalone
    ├── googledorks_lookup.py   ← Google Dorks via SerpAPI standalone
    ├── shodan_lookup.py        ← Shodan standalone (+ InternetDB fallback)
    ├── urlhaus_lookup.py       ← URLhaus standalone
    └── virustotal_lookup.py    ← VirusTotal standalone (IP / URL / Hash / --full)
```

---

## Exemple de sortie — mode IP

Si la cible a déjà été analysée dans la durée du cache configurée (24h par défaut), le résultat est chargé depuis le cache (sans appel API) :
```
  IOC Hunting  ›  1.2.3.4  (cache)
```

```
════════════════════════════════════════════════════════════════════════

  IOC Hunting  ›  1.2.3.4

  Score de menace  ████████████████░░░░  80/100  [CRITIQUE]

  Signaux détectés
    ·  AbuseIPDB 100%
    ·  VT 8 détections
    ·  URLhaus online (2)

────────────────────────────────────────────────────────────────────────
  Détails par source

  AbuseIPDB                  score 100%  |  121 rapports  |  APNIC (UA)
  VirusTotal                 8/91 moteurs  |  1 suspects  |  Tags : scanner, vpn
  Shodan                     3 ports  |  0 CVE(s)
  Censys                     6 ports
  URLhaus                    is_host  |  online: 2  |  botnet_cc
```

## Exemple de sortie — mode Hash

```
════════════════════════════════════════════════════════════════════════

  IOC Hunting — Hash  ›  db349b97c37d22f5ea1d1841e3c89eb4

  Score de menace  ████████████████████  95/100  [CRITIQUE]

  Signaux détectés
    ·  VT 67 détections
    ·  YARA 5 match(es)
    ·  Sandbox malicious (3)
    ·  URLhaus référencé (offline)
    ·  Famille: WannaCry

────────────────────────────────────────────────────────────────────────
  URLhaus — Payload

  Famille / Signature        WannaCry
  Type fichier               exe
  Taille                     3723264 bytes
  SHA256                     ed01ebfbc9eb5bbea545af4d01bf5f1071661840...

────────────────────────────────────────────────────────────────────────
  VirusTotal — Fichier

  Détections                 67/72 moteurs
  ...
  Crowdsourced YARA Rules    (5 matches)
  Crowdsourced Sigma Rules   critical: 2  high: 3
  Dynamic Analysis           Sandbox → malicious (WannaCry.Ransomware)
```

---

## Limitations

- **VirusTotal plan gratuit** : 4 requêtes/minute, 500/jour. Le script attend automatiquement sur rate limit (429). L'analyse de plusieurs hashes consécutifs prend ~16 secondes entre chaque.
- **Shodan plan gratuit** : accès limité aux données indexées via `/shodan/host/{ip}`. Sans clé, fallback automatique sur InternetDB.
- **AbuseIPDB** : 1 000 requêtes/jour (plan gratuit).
- **Censys** : 250 requêtes/mois (plan gratuit).
- **URLhaus** : pas de limite officielle sur le plan gratuit, mais un usage raisonnable est recommandé.

---

## Dépendances

- **Python 3.10+** (requis pour la syntaxe `set | None` dans les annotations de type)
- `cryptography >= 41.0.0` (chiffrement Fernet des clés API)

Toutes les autres dépendances (`urllib`, `json`, `argparse`, `hashlib`, `concurrent.futures`, `base64`, `re`, `getpass`) font partie de la bibliothèque standard Python.

---

## Désinstallation

Supprime le dossier du projet, puis les données locales générées par le script :

```bash
rm -rf ~/.config/ioc_hunting/
```

Ce dossier contient les clés API (chiffrées ou non), le cache des résultats et les paramètres (port web, durée du cache).

---

*Made by hsa5*

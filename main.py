#!/usr/bin/env python3
# Made by hsa5
"""
IOC Hunting — Corrélation multi-sources
==========================================
Point d'entrée principal. Deux modes d'analyse :

  Mode IP/URL  : interroge AbuseIPDB, VirusTotal, Shodan, Censys et URLhaus
                 en parallèle (ThreadPoolExecutor) et génère un rapport unifié.

  Mode Hash    : interroge VirusTotal (/files/<hash>) et URLhaus (/payload/)
                 en parallèle. Peut aussi hasher des fichiers locaux (SHA256).

Auto-détection : si toutes les cibles passées en CLI sont des hashes
(32/40/64 hex chars), le mode hash est activé automatiquement.

Usage direct  :
  python main.py 1.2.3.4
  python main.py https://malicious.example.com
  python main.py d41d8cd98f00b204e9800998ecf8427e   ← hash auto-détecté
  python main.py --file targets.txt --export rapport.json
  python main.py 1.2.3.4 --year 2025,2026
  python main.py --type hash                        ← force mode hash
  python main.py --type ip 1.2.3.4                 ← force mode IP

Première utilisation : python setup.py
"""

import sys
import os
import json
import base64
import argparse
import re
import time
import datetime
import hashlib
import socket
import csv
import shutil
import glob
import urllib.parse
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import readline as _readline
    def _input_path(prompt):
        def _completer(text, state):
            matches = glob.glob(os.path.expanduser(text) + '*')
            matches = [m + os.sep if os.path.isdir(m) else m for m in matches]
            return matches[state] if state < len(matches) else None
        _readline.set_completer(_completer)
        _readline.set_completer_delims(' \t\n')
        _readline.parse_and_bind('tab: complete')
        try:
            return input(prompt).strip()
        finally:
            _readline.set_completer(None)
except ImportError:
    def _input_path(prompt):
        return input(prompt).strip()

_internal_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".internal")
if _internal_path not in sys.path:
    sys.path.insert(0, _internal_path)
from config_loader import load_key, all_keys, SERVICES, load_setting

_modules_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "modules")
if _modules_path not in sys.path:
    sys.path.insert(0, _modules_path)
from virustotal_lookup import (
    vt_get              as _vt_get,
    vt_get_retry        as _vt_get_retry,
    _render_detections  as _vt_render_detections,
    _render_yara_rules,
    _render_sigma_rules,
    _render_crowdsourced_ids,
    _render_sandbox_verdicts,
)

RESET  = "\033[0m";  BOLD  = "\033[1m";  DIM  = "\033[2m"
RED    = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
CYAN   = "\033[96m"; WHITE = "\033[97m"

def c(text, *codes): return "".join(codes) + str(text) + RESET
def sep(ch="─", w=72): print(c(ch * w, DIM))

# Précis : 32=MD5, 40=SHA1, 64=SHA256. Pas de range 32-64 qui accepterait des longueurs invalides.
_RE_HASH = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")

def is_ip(s):
    for af in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(af, s)
            return True
        except (socket.error, OSError):
            pass
    return False

def is_ipv4(s):
    try:
        socket.inet_pton(socket.AF_INET, s)
        return True
    except (socket.error, OSError):
        return False

_RE_DOMAIN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

def is_domain(s):
    return bool(_RE_DOMAIN.match(s)) and not is_ip(s) and not is_hash(s)

def is_url(s):  return s.startswith("http://") or s.startswith("https://")
def is_hash(s): return bool(_RE_HASH.match(s))

def extract_host_from_url(url):
    try:
        return urllib.parse.urlparse(url).hostname or ""
    except Exception:
        return ""

def parse_years(year_str: str) -> set | None:
    """'2025,2026' → {2025, 2026}. None si vide — signifie "pas de filtre"."""
    if not year_str:
        return None
    years = {int(p.strip()) for p in year_str.split(",") if p.strip().isdigit()}
    return years or None

def ts_to_year(ts) -> int | None:
    try:
        return datetime.datetime.fromtimestamp(int(ts)).year
    except Exception:
        return None

# ── cache ──────────────────────────────────────────────────────────────────────
# Stocke les résultats d'analyse dans ~/.config/ioc_hunting/cache.json
# Format : { "cible|years": {"ts": float, "data": {...}} }
# Expiration : 24h glissantes (pas par jour calendaire, pour éviter les coupures à minuit)
# Désactivable via --nocache pour forcer des requêtes API fraîches

_CACHE_FILE = os.path.expanduser("~/.config/ioc_hunting/cache.json")
_CACHE_MAX  = 500   # nombre max d'entrées avant avertissement
_CACHE_TTL  = 86400 # durée par défaut (24h) — remplacée au lancement par la config

def _cache_load() -> dict:
    # Retourne {} si le fichier n'existe pas encore ou est corrompu
    try:
        with open(_CACHE_FILE) as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def _cache_save(cache: dict):
    # Écriture atomique : écrit dans .tmp puis os.replace() — jamais de fichier corrompu
    # même si Ctrl+C intervient pendant la sauvegarde
    os.makedirs(os.path.dirname(_CACHE_FILE), exist_ok=True)
    tmp = _CACHE_FILE + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(cache, fh, separators=(",", ":"))
    os.replace(tmp, _CACHE_FILE)

def _cache_purge(cache: dict) -> int:
    # Supprime toutes les entrées dont le timestamp dépasse _CACHE_TTL secondes
    cutoff  = time.time() - _CACHE_TTL
    expired = [k for k, v in cache.items() if v.get("ts", 0) < cutoff]
    for k in expired:
        del cache[k]
    return len(expired)

def _cache_key(target: str, years) -> str:
    # Inclut le filtre years dans la clé pour éviter les collisions entre requêtes
    # ex: "1.2.3.4|2024,2025" et "1.2.3.4" sont deux entrées distinctes
    return f"{target}|{','.join(str(y) for y in sorted(years))}" if years else target

def _cache_get(cache: dict, key: str) -> dict | None:
    # Retourne None si entrée absente ou expirée (vérifie _CACHE_TTL glissant)
    entry = cache.get(key)
    if entry and time.time() - entry.get("ts", 0) <= _CACHE_TTL:
        return entry.get("data")
    return None

def _cache_set(cache: dict, key: str, data: dict):
    # Enregistre le résultat avec le timestamp courant
    cache[key] = {"ts": time.time(), "data": data}

# ── wrappers HTTP de base ──────────────────────────────────────────────────────

def _urlhaus_post(endpoint, payload, key):
    """POST vers l'API URLhaus. Lève ValueError si la réponse est vide ou HTML
    (abuse.ch renvoie du HTML quand la clé est invalide ou le rate-limit atteint)."""
    data = urllib.parse.urlencode(payload).encode()
    req  = urllib.request.Request(endpoint, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("Auth-Key", key)
    with urllib.request.urlopen(req, timeout=10) as resp:
        raw = resp.read()
    if not raw or not raw.strip():
        raise ValueError("URLhaus: réponse vide — clé API invalide ou rate-limit")
    text = raw.decode("utf-8", errors="replace")
    if text.lstrip().startswith("<"):
        raise ValueError("URLhaus: réponse HTML — clé invalide ou rate-limit")
    return json.loads(text)

def _vt_relationship(path, key, limit=40):
    """Appelle un endpoint relationship VT (ex: /ip_addresses/{ip}/communicating_files).
    Retourne (liste items, count total). 404 → liste vide sans erreur."""
    try:
        data = _vt_get_retry(f"{path}?limit={limit}", key, label=f"[{path.split('/')[-1]}] ")
        return data.get("data", []), data.get("meta", {}).get("count", 0)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return [], 0
        raise

# ── fetch par source ───────────────────────────────────────────────────────────
# Chaque fonction fetch_* suit la même convention de retour :
#   {"_skipped": "no key"}   → clé API absente, source ignorée silencieusement
#   {"_not_found": True}     → 404, IP non indexée
#   {"_error": "..."}        → erreur réseau ou API (affiché comme avertissement)
#   {...données réelles...}  → succès
# safe_fetch() enveloppe chaque call pour que les erreurs ne cassent pas les autres threads.

def fetch_abuseipdb(ip, key):
    if not key:
        return {"_skipped": "no key"}
    params = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""})
    req = urllib.request.Request(f"https://api.abuseipdb.com/api/v2/check?{params}")
    req.add_header("Key", key)
    req.add_header("Accept", "application/json")
    with urllib.request.urlopen(req, timeout=12) as resp:
        return json.loads(resp.read().decode())

def fetch_virustotal_ip(ip, key):
    if not key:
        return {"_skipped": "no key"}
    return _vt_get_retry(f"/ip_addresses/{urllib.parse.quote(ip, safe='')}", key)

def fetch_virustotal_domain(domain, key):
    if not key:
        return {"_skipped": "no key"}
    return _vt_get_retry(f"/domains/{urllib.parse.quote(domain, safe='')}", key)

def fetch_virustotal_url(url_target, key):
    if not key:
        return {"_skipped": "no key"}
    # L'ID d'une URL dans VT est son encodage base64url sans padding
    url_id = base64.urlsafe_b64encode(url_target.encode()).rstrip(b"=").decode()
    try:
        return _vt_get_retry(f"/urls/{url_id}", key)
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise
        # URL inconnue → la soumettre pour analyse, puis attendre completion
        data   = urllib.parse.urlencode({"url": url_target}).encode()
        req2   = urllib.request.Request("https://www.virustotal.com/api/v3/urls", data=data, method="POST")
        req2.add_header("x-apikey", key)
        req2.add_header("Content-Type", "application/x-www-form-urlencoded")
        with urllib.request.urlopen(req2, timeout=12) as r:
            sub = json.loads(r.read().decode())
        analysis_id = sub.get("data", {}).get("id", "")
        for _ in range(5):
            time.sleep(6)
            try:
                an = _vt_get(f"/analyses/{analysis_id}", key)
                if an.get("data", {}).get("attributes", {}).get("status") == "completed":
                    return _vt_get_retry(f"/urls/{url_id}", key)
            except Exception:
                pass
        return {"_error": "analyse VT non terminée"}

def _fetch_internetdb(ip):
    """Shodan InternetDB — endpoint public, gratuit, sans clé API.
    Fournit ports/vulns/CPEs/hostnames mais pas les détails de services.
    Retourné dans un format normalisé compatible avec _render_mini_shodan()."""
    url = f"https://internetdb.shodan.io/{urllib.parse.quote(ip, safe='')}"
    with urllib.request.urlopen(url, timeout=10) as resp:
        data = json.loads(resp.read().decode())
    # normalise au même format que /shodan/host/{ip} pour le rendu
    return {
        "_source":   "internetdb",
        "ports":     data.get("ports") or [],
        "vulns":     data.get("vulns") or [],
        "hostnames": data.get("hostnames") or [],
        "tags":      data.get("tags") or [],
        "cpes":      data.get("cpes") or [],
        "org":       "",
        "isp":       "",
        "country_name": "",
    }

def fetch_shodan(ip, key):
    """Essaie d'abord /shodan/host/{ip} (clé requise), puis fallback sur InternetDB si
    pas de clé ou erreur 401/403. Un fallback transparent évite de bloquer le rapport
    entier quand le plan Shodan ne couvre pas l'endpoint."""
    if not key:
        # Pas de clé → essaye quand même InternetDB (gratuit)
        try:
            return _fetch_internetdb(ip)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {"_not_found": True}
            return {"_skipped": "no key"}
        except Exception:
            return {"_skipped": "no key"}

    url = f"https://api.shodan.io/shodan/host/{urllib.parse.quote(ip, safe='')}?key={urllib.parse.quote(key, safe='')}"
    try:
        with urllib.request.urlopen(url, timeout=12) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"_not_found": True}
        if e.code in (401, 403):
            # Fallback automatique sur InternetDB
            try:
                data = _fetch_internetdb(ip)
                data["_fallback"] = True
                return data
            except urllib.error.HTTPError as e2:
                if e2.code == 404:
                    return {"_not_found": True}
                return {"_forbidden": True}
            except Exception:
                return {"_forbidden": True}
        raise

def fetch_urlhaus_url(url_target, key):
    if not key:
        return {"_skipped": "no key"}
    return _urlhaus_post("https://urlhaus-api.abuse.ch/v1/url/", {"url": url_target}, key)

def fetch_urlhaus_host(host, key):
    if not key:
        return {"_skipped": "no key"}
    return _urlhaus_post("https://urlhaus-api.abuse.ch/v1/host/", {"host": host}, key)

_CENSYS_UA = "censys-python/2.2.12 (+https://github.com/censys/censys-python)"

def fetch_censys(ip, key):
    if not key:
        return {"_skipped": "no key"}
    url = f"https://api.platform.censys.io/v3/global/asset/host/{urllib.parse.quote(ip, safe='')}"
    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Bearer {key}")
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", _CENSYS_UA)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"_not_found": True}
        if e.code == 429:
            return {"_error": "quota atteint (250 req/mois — plan gratuit)"}
        raise

_GD_PRIORITY_KEYWORDS = {
    "botnet", "malware", "phishing", "ransomware", "c2", "c&c", "command and control",
    "threat", "ioc", "indicator", "compromise", "exploit", "trojan", "rat ", "backdoor",
    "campaign", "apt", "intrusion", "attack", "payload",
}

def _gd_priority_score(item: dict) -> int:
    """Retourne 1 si l'item contient un mot-clé CTI dans le titre/snippet/url, 0 sinon."""
    text = " ".join([
        (item.get("title") or ""),
        (item.get("snippet") or ""),
        (item.get("link") or ""),
    ]).lower()
    return 1 if any(kw in text for kw in _GD_PRIORITY_KEYWORDS) else 0

def fetch_googledorks(target: str, key: str) -> dict:
    if not key:
        return {"_skipped": "no key"}
    try:
        from modules.googledorks_lookup import query as _gd_query, _filter as _gd_filter
        data  = _gd_query(target, key)
        items = _gd_filter(data.get("organic_results") or [], target)
        items.sort(key=_gd_priority_score, reverse=True)
        return {"items": items, "total": str(data.get("total", ""))}
    except Exception as e:
        return {"_error": str(e)}

def safe_fetch(name, fn, *args):
    """Enveloppe une fonction fetch dans un try/except pour ThreadPoolExecutor.
    Retourne (nom, données, erreur_str). KeyboardInterrupt n'est PAS attrapé —
    il se propage et est géré par le handler global dans __main__."""
    try:
        return name, fn(*args), None
    except Exception as e:
        return name, None, str(e)

def fetch_virustotal_hash(h: str, key: str) -> dict:
    """Interroge VT /files/{hash}. Fonctionne avec MD5, SHA1 ou SHA256."""
    if not key:
        return {"_skipped": "no key"}
    return _vt_get_retry(f"/files/{h}", key)

def fetch_urlhaus_hash(h: str, key: str) -> dict:
    """Interroge URLhaus /v1/payload/ pour un hash.
    Le champ envoyé dépend de la longueur : sha256_hash (64 chars) ou md5_hash (32)."""
    if not key:
        return {"_skipped": "no key"}
    field = "sha256_hash" if len(h) == 64 else "md5_hash"
    return _urlhaus_post("https://urlhaus-api.abuse.ch/v1/payload/", {field: h}, key)

# ── filtre fichiers VT ─────────────────────────────────────────────────────────

def filter_vt_files(items: list, years: set | None, min_malicious: int = 1) -> list:
    """Filtre les fichiers VT (communicating/referrer) : garde seulement ceux
    détectés par au moins min_malicious moteurs, et optionnellement dans une
    des années demandées."""
    out = []
    for item in items:
        attr = item.get("attributes", {})
        mal  = attr.get("last_analysis_stats", {}).get("malicious", 0)
        if mal < min_malicious:
            continue
        if years:
            ts   = attr.get("last_analysis_date") or attr.get("first_submission_date")
            year = ts_to_year(ts)
            if year not in years:
                continue
        out.append(item)
    return out

# ── score ──────────────────────────────────────────────────────────────────────
# Les scores sont additifs et plafonnés à 100 (min(score, 100)).
# Les seuils sont volontairement asymétriques : AbuseIPDB >= 75% pèse +40 car
# c'est un signal très fiable ; Shodan CVEs pèsent moins car souvent des faux positifs.

def score_from_results(results):
    """Calcule le score de menace 0-100 pour une IP/URL à partir de tous les résultats.
    Retourne (score: int, signals: list[str colorisé])."""
    score, signals = 0, []

    abuse = results.get("abuseipdb", {})
    if abuse and not abuse.get("_skipped") and not abuse.get("_error"):
        pct = abuse.get("data", {}).get("abuseConfidenceScore", 0)
        if pct >= 75:   score += 40; signals.append(c(f"AbuseIPDB {pct}%", RED, BOLD))
        elif pct >= 25: score += 20; signals.append(c(f"AbuseIPDB {pct}%", YELLOW))
        elif pct > 0:   score += 5;  signals.append(c(f"AbuseIPDB {pct}%", DIM))

    vt = results.get("virustotal", {})
    if vt and not vt.get("_skipped") and not vt.get("_error"):
        stats = vt.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        mal, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
        if mal > 5:   score += 35; signals.append(c(f"VT {mal} détections", RED, BOLD))
        elif mal > 0: score += 20; signals.append(c(f"VT {mal} détections", YELLOW))
        elif sus > 0: score += 8;  signals.append(c(f"VT {sus} suspects", DIM))

    shodan = results.get("shodan", {})
    if shodan and not shodan.get("_skipped") and not shodan.get("_error"):
        vulns = shodan.get("vulns") or []
        if vulns:
            score += min(len(vulns) * 5, 20)
            signals.append(c(f"Shodan {len(vulns)} CVE(s)", YELLOW))
        if "malware" in (shodan.get("tags") or []) or "compromised" in (shodan.get("tags") or []):
            score += 15; signals.append(c("Shodan tag malware/compromised", RED))

    urlhaus = results.get("urlhaus", {})
    if urlhaus and not urlhaus.get("_skipped") and not urlhaus.get("_error"):
        qs  = urlhaus.get("query_status", "")
        urls = urlhaus.get("urls") or []
        n_on = len([u for u in urls if u.get("url_status") == "online"])
        if n_on > 0:   score += 30; signals.append(c(f"URLhaus online ({n_on})", RED, BOLD))
        elif qs not in ("no_results", "is_clean", ""):
            score += 10; signals.append(c("URLhaus référencé (offline)", YELLOW))

    return min(score, 100), signals

def threat_level(score):
    if score >= 70: return c("CRITIQUE", RED, BOLD),  RED
    if score >= 40: return c("ÉLEVÉ",    RED),         RED
    if score >= 15: return c("MODÉRÉ",   YELLOW, BOLD), YELLOW
    return           c("FAIBLE",  GREEN),              GREEN

def score_from_hash_results(results: dict) -> tuple:
    """Version hash du score : prend en compte VT detections, YARA, IDS, Sigma,
    Sandbox verdicts et URLhaus. Retourne (score: int, signals: list[str colorisé])."""
    score, signals = 0, []

    vt = results.get("virustotal", {})
    if vt and not vt.get("_skipped") and not vt.get("_error"):
        attr  = vt.get("data", {}).get("attributes", {})
        stats = attr.get("last_analysis_stats", {})
        mal   = stats.get("malicious", 0)
        sus   = stats.get("suspicious", 0)
        if   mal > 10: score += 50; signals.append(c(f"VT {mal} détections", RED, BOLD))
        elif mal >  3: score += 35; signals.append(c(f"VT {mal} détections", RED, BOLD))
        elif mal >  0: score += 20; signals.append(c(f"VT {mal} détections", YELLOW))
        elif sus >  0: score +=  8; signals.append(c(f"VT {sus} suspects", DIM))

        yara = attr.get("crowdsourced_yara_results") or []
        if yara:
            score += 10
            signals.append(c(f"YARA {len(yara)} match(es)", YELLOW))

        ids_stats = attr.get("crowdsourced_ids_stats") or {}
        if ids_stats.get("high", 0):
            score += 10
            signals.append(c(f"IDS high ({ids_stats['high']})", RED))
        elif ids_stats.get("medium", 0):
            score += 5
            signals.append(c(f"IDS medium ({ids_stats['medium']})", YELLOW))

        sigma = attr.get("sigma_analysis_stats") or {}
        n_sig = sigma.get("critical", 0) + sigma.get("high", 0)
        if n_sig:
            score += 10
            signals.append(c(f"Sigma high/critical ({n_sig})", RED))

        verdicts = attr.get("sandbox_verdicts") or {}
        mal_sbox = [s for s, v in verdicts.items() if v.get("category") == "malicious"]
        if mal_sbox:
            score += 15
            signals.append(c(f"Sandbox malicious ({len(mal_sbox)})", RED, BOLD))

    urlhaus = results.get("urlhaus", {})
    if urlhaus and not urlhaus.get("_skipped") and not urlhaus.get("_error"):
        if urlhaus.get("query_status") == "ok":
            urls = urlhaus.get("urls") or []
            n_on = len([u for u in urls if u.get("url_status") == "online"])
            sig  = urlhaus.get("signature") or ""
            if n_on > 0:
                score += 25
                signals.append(c(f"URLhaus online ({n_on} URL)", RED, BOLD))
            else:
                score += 10
                signals.append(c("URLhaus référencé (offline)", YELLOW))
            if sig:
                signals.append(c(f"Famille: {sig}", RED))

    return min(score, 100), signals

# ── render ─────────────────────────────────────────────────────────────────────
# Hiérarchie du rendu :
#   render_summary()     → bandeau score + signaux
#   render_details()     → tableau résumé par source + sections détaillées
#     _render_mini_*()   → une ligne par source dans le tableau résumé
#     render_censys_services() / render_urlhaus_hashes() / render_vt_*() → sections détail

def render_summary(target, results, score, signals, cached=False):
    sep("═")
    cache_s = c("  (cache)", DIM) if cached else ""
    print(f"\n  {c('IOC Hunting', BOLD, WHITE)}  {c('›', DIM)}  {c(target, CYAN, BOLD)}{cache_s}\n")
    level_label, level_col = threat_level(score)
    bar = c("█" * int(score / 5), level_col) + c("░" * (20 - int(score / 5)), DIM)
    print(f"  {c('Score de menace', BOLD)}  {bar}  {c(f'{score}/100', level_col, BOLD)}  [{level_label}]")
    print()
    if signals:
        print(f"  {c('Signaux détectés', BOLD)}")
        for s in signals:
            print(f"    {c('·', DIM)}  {s}")
    else:
        print(f"  {c('·  Aucun signal malveillant détecté', GREEN)}")
    print()

def _render_mini_abuseipdb(data):
    if not data or data.get("_skipped"): return
    if data.get("_error"):
        print(f"  {c('⚠', YELLOW)}  AbuseIPDB : {c(data['_error'], DIM)}"); return
    d     = data.get("data", {})
    score = d.get("abuseConfidenceScore", 0)
    col   = RED + BOLD if score >= 75 else (YELLOW if score >= 25 else GREEN)
    print(f"  {c('AbuseIPDB', BOLD):<28}  score {c(f'{score}%', col)}"
          f"  |  {d.get('totalReports',0)} rapports"
          f"  |  {d.get('isp','n/a')} ({d.get('countryCode','?')})")

def _render_mini_virustotal(data):
    if not data or data.get("_skipped"): return
    if data.get("_error"):
        print(f"  {c('⚠', YELLOW)}  VirusTotal : {c(data['_error'], DIM)}"); return
    attr  = data.get("data", {}).get("attributes", {})
    stats = attr.get("last_analysis_stats", {})
    mal   = stats.get("malicious", 0)
    sus   = stats.get("suspicious", 0)
    total = sum(stats.values())
    col   = RED + BOLD if mal > 0 else (YELLOW if sus > 0 else GREEN)
    tags  = attr.get("tags") or []
    tags_s = f"  |  {c('Tags', BOLD)} : {c(', '.join(tags), CYAN)}" if tags else ""
    print(f"  {c('VirusTotal', BOLD):<28}  {c(f'{mal}', col)}/{total} moteurs  |  {sus} suspects{tags_s}")

def _render_mini_shodan(data):
    if not data or data.get("_skipped"): return
    if data.get("_not_found"):
        print(f"  {c('Shodan', BOLD):<28}  {c('aucune donnée indexée pour cette IP', DIM)}")
        return
    if data.get("_forbidden"):
        print(f"  {c('Shodan', BOLD):<28}  {c('accès refusé (403) — clé invalide/crédits épuisés', YELLOW)}"
              f"  {c('→ account.shodan.io', DIM)}")
        return
    if data.get("_error"): return

    ports  = data.get("ports") or []
    vulns  = data.get("vulns") or []
    org    = data.get("org") or data.get("isp") or ""
    source = c(" [InternetDB]", DIM) if data.get("_source") == "internetdb" else ""
    suffix = c(" [fallback InternetDB]", DIM) if data.get("_fallback") else ""
    col    = RED if vulns else (YELLOW if len(ports) > 10 else DIM)
    org_s  = f"  |  {org}" if org else ""
    print(f"  {c('Shodan', BOLD):<28}  {len(ports)} ports  |  {c(len(vulns), col)} CVE(s){org_s}{source}{suffix}")

    # Ports détaillés (CPEs si dispo)
    if ports:
        cpes = data.get("cpes") or []
        ports_s = "  ".join(c(str(p), YELLOW) for p in sorted(ports)[:20])
        print(f"  {'':<28}  {ports_s}")
        if cpes:
            print(f"  {'':<28}  {c('CPE: ', DIM)}" +
                  c(", ".join(cpes[:4]), DIM))

    # CVEs
    if vulns:
        vulns_s = "  ".join(c(v, RED) for v in sorted(vulns)[:8])
        print(f"  {'':<28}  {c('CVE: ', DIM)}{vulns_s}")

def _render_mini_urlhaus(data):
    if not data or data.get("_skipped"): return
    if data.get("_error"):
        print(f"  {c('⚠', YELLOW)}  URLhaus : {c(data['_error'], DIM)}"); return
    qs   = data.get("query_status", "")
    urls = data.get("urls") or []
    n_on = len([u for u in urls if u.get("url_status") == "online"])
    if qs in ("no_results", "is_clean", ""):
        print(f"  {c('URLhaus', BOLD):<28}  {c('non référencé', GREEN)}"); return
    threat = (", ".join(dict.fromkeys(u.get("threat","") for u in urls if u.get("threat")))
              or data.get("threat") or "n/a")
    col = RED + BOLD if n_on > 0 else YELLOW
    print(f"  {c('URLhaus', BOLD):<28}  {c(qs, col)}  |  online: {c(n_on, col)}  |  {threat}")

def _render_mini_vt_hash(data: dict):
    if not data or data.get("_skipped"): return
    if data.get("_error"):
        print(f"  {c('⚠', YELLOW)}  VirusTotal : {c(data['_error'], DIM)}"); return
    attr  = data.get("data", {}).get("attributes", {})
    stats = attr.get("last_analysis_stats", {})
    mal   = stats.get("malicious", 0)
    sus   = stats.get("suspicious", 0)
    total = sum(stats.values())
    col   = RED + BOLD if mal > 0 else (YELLOW if sus > 0 else GREEN)
    names = (attr.get("names") or [])[:1]
    name_s = f"  |  {names[0][:40]}" if names else ""
    tags   = attr.get("tags") or []
    tags_s = f"  |  {c('Tags', BOLD)} : {c(', '.join(tags), CYAN)}" if tags else ""
    print(f"  {c('VirusTotal', BOLD):<28}  {c(f'{mal}', col)}/{total} moteurs  |  {sus} suspects{name_s}{tags_s}")

def _render_mini_urlhaus_hash(data: dict):
    if not data or data.get("_skipped"): return
    if data.get("_error"):
        print(f"  {c('⚠', YELLOW)}  URLhaus : {c(data['_error'], DIM)}"); return
    if data.get("query_status") != "ok":
        print(f"  {c('URLhaus', BOLD):<28}  {c('hash non référencé', GREEN)}"); return
    urls  = data.get("urls") or []
    n_on  = len([u for u in urls if u.get("url_status") == "online"])
    sig   = data.get("signature") or "sig inconnue"
    ftype = data.get("file_type") or "?"
    col   = RED + BOLD if n_on > 0 else YELLOW
    print(f"  {c('URLhaus', BOLD):<28}  {c('TROUVÉ', col)}"
          f"  |  {c(sig, RED)}  |  {ftype}"
          f"  |  {len(urls)} URL(s)  online: {c(n_on, col)}")

def _render_mini_censys(data):
    if not data or data.get("_skipped"): return
    if data.get("_not_found"):
        print(f"  {c('Censys', BOLD):<28}  {c('IP non indexée', DIM)}"); return
    if data.get("_error"):
        print(f"  {c('⚠', YELLOW)}  Censys : {c(data['_error'], DIM)}"); return
    resource = data.get("result", {}).get("resource", {})
    services = resource.get("services") or []
    ports    = sorted({s["port"] for s in services if s.get("port")})
    col      = YELLOW if ports else DIM
    print(f"  {c('Censys', BOLD):<28}  {c(len(ports), col)} ports")
    if ports:
        print(f"  {'':<28}  " + "  ".join(c(str(p), YELLOW) for p in ports[:20]))

def render_censys_services(data):
    if not data or data.get("_skipped") or data.get("_not_found") or data.get("_error"):
        return
    resource = data.get("result", {}).get("resource", {})
    services = resource.get("services") or []
    if not services:
        return
    sep()
    print(f"  {c('Censys — Services', BOLD, WHITE)}  {c(f'({len(services)} détectés)', DIM)}\n")
    for svc in services:
        port    = svc.get("port", "?")
        proto   = (svc.get("transport_protocol") or "tcp").upper()
        name    = svc.get("protocol") or svc.get("service_name") or "?"
        sw_list = svc.get("software") or []
        sw_s    = ""
        if sw_list:
            sw    = sw_list[0]
            parts = [sw.get("vendor", ""), sw.get("product", "")]
            sw_s  = "  " + c(" ".join(p for p in parts if p), DIM)
        labels = [l.get("value", "") if isinstance(l, dict) else str(l)
                  for l in (svc.get("labels") or [])]
        print(f"  {c(f'{port}/{proto}', YELLOW, BOLD):<28}  {c(name, WHITE)}{sw_s}")
        if labels:
            print(f"    {c('Labels:', DIM)}  {c(', '.join(labels[:4]), CYAN)}")
    print()

def render_urlhaus_hashes(data, show_offline=False):
    """Affiche les hashes des payloads malwares associés à une IP/host dans URLhaus.
    Ces payloads sont collectés en phase 1b via des requêtes individuelles sur chaque URL."""
    if not data or data.get("_skipped") or data.get("_error"):
        return
    payloads = data.get("payloads") or []
    if not payloads:
        return
    if not show_offline:
        visible = [p for p in payloads if p.get("_url_status") != "offline"]
        hidden  = len(payloads) - len(visible)
    else:
        visible = payloads
        hidden  = 0
    if not visible and not show_offline:
        return
    sep()
    print(f"  {c('URLhaus — Payloads / Hashes malwares', BOLD, WHITE)}"
          f"  {c(f'({len(visible)} payload(s))', DIM)}\n")
    for p in visible:
        sig       = p.get("signature") or "unknown"
        ftype     = p.get("file_type") or "?"
        sha       = p.get("response_sha256") or p.get("sha256") or ""
        md5       = p.get("response_md5")   or p.get("md5") or ""
        url       = p.get("url") or ""
        date      = (p.get("firstseen") or "")[:10]
        fname     = p.get("filename") or ""
        vt        = p.get("virustotal") or {}
        vt_r      = vt.get("result", "")
        vt_p      = vt.get("percent", "")
        status    = p.get("_url_status", "")
        status_s  = (c(" ONLINE ", GREEN + BOLD) if status == "online"
                     else c(" offline ", DIM) if status == "offline"
                     else "")

        print(f"    {c('⚠', RED)}  {c(sig, RED, BOLD):<30}  "
              f"{c(f'[{ftype}]', YELLOW)}  {c(date, DIM)}  {status_s}")
        if fname:
            print(f"         {c('Fichier :', DIM)}  {c(fname, WHITE)}")
        if url:
            print(f"         {c('URL     :', DIM)}  {c(url, CYAN)}")
        if sha:
            print(f"         {c('SHA256  :', DIM)}  {c(sha, CYAN, BOLD)}")
        if md5:
            print(f"         {c('MD5     :', DIM)}  {c(md5, DIM)}")
        if vt_r:
            col = RED if vt_p and float(vt_p) > 0 else DIM
            print(f"         {c('VT      :', DIM)}  {c(f'{vt_r}  ({vt_p}%)', col)}")
        print()
    if hidden:
        print(c(f"  ({hidden} payload(s) offline masqué(s) — --offline pour tout afficher)", DIM))

def render_vt_crowdsourced_context(data):
    if not data or data.get("_skipped") or data.get("_error"):
        return
    items = (data.get("data", {}).get("attributes", {})
             .get("crowdsourced_context") or [])
    if not items:
        return
    sep()
    print(f"  {c('VirusTotal — Crowdsourced Context', BOLD, WHITE)}"
          f"  {c(f'({len(items)} entrée(s))', DIM)}\n")
    for item in items:
        title_s   = item.get("title", "")
        source    = item.get("source", "")
        severity  = (item.get("severity") or "").lower()
        details   = (item.get("details") or "").strip()
        ts        = item.get("timestamp")

        date_str = ""
        if ts:
            try:
                date_str = datetime.datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d")
            except Exception:
                pass

        sev_col = RED + BOLD if severity == "high" else (YELLOW if severity == "medium" else DIM)
        sev_s   = c(f" [{severity}]", sev_col) if severity else ""
        src_s   = c(f"  —  {source}", DIM) if source else ""
        date_s  = c(f"  ({date_str})", CYAN) if date_str else ""

        print(f"  {c('▸', sev_col)}  {c(title_s, WHITE, BOLD)}{src_s}{date_s}{sev_s}")
        if details:
            for line in details.split("\n")[:4]:
                line = line.strip()
                if line:
                    print(f"     {c(line[:110], DIM)}")
        print()

def render_vt_file_section(items: list, count_total: int, title: str, years: set | None):
    """Affiche une section de fichiers VT (communicating_files ou referrer_files).
    items = résultat de filter_vt_files() (déjà filtré malicious >= 1)."""
    if not items:
        return
    year_label = f"  filtre: {', '.join(str(y) for y in sorted(years))}" if years else ""
    sep()
    print(f"  {c(title, BOLD, WHITE)}"
          f"  {c(f'({len(items)} affichés / {count_total} total{year_label})', DIM)}\n")
    for item in items:
        attr  = item.get("attributes", {})
        sha   = item.get("id", "")
        names = (attr.get("names") or [])[:2]
        name  = ", ".join(names) or attr.get("meaningful_name", "?")
        ftype = attr.get("type_description", "")
        stats = attr.get("last_analysis_stats", {})
        mal   = stats.get("malicious", 0)
        total = sum(stats.values()) or 1
        col   = RED + BOLD if mal > 5 else RED if mal > 0 else DIM
        ts    = attr.get("last_analysis_date") or attr.get("first_submission_date")
        date  = ""
        if ts:
            try:
                date = datetime.datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d")
            except Exception:
                pass

        print(f"    {c(f'{mal}/{total}', col):<12}  {c(date, DIM):<14}  {c(name[:50], WHITE)}  {c(f'[{ftype}]', DIM)}")
        print(f"               {c('SHA256:', DIM)} {c(sha, CYAN)}")
        print()

def render_urlhaus_hash_section(data: dict):
    """Affiche les détails URLhaus pour un hash (payload) : famille, type, taille,
    dates, MD5/SHA256, tags, résultat VT (depuis URLhaus), URLs de distribution."""
    if not data or data.get("_skipped") or data.get("_error"):
        return
    if data.get("query_status") != "ok":
        return
    sep()
    sig   = data.get("signature") or "inconnu"
    ftype = data.get("file_type") or "?"
    fsz   = data.get("file_size")
    first = (data.get("firstseen") or "")[:16]
    last  = (data.get("lastseen")  or "")[:16]
    md5   = data.get("md5_hash")   or ""
    sha   = data.get("sha256_hash") or ""
    tags  = data.get("tags") or []
    urls  = data.get("urls") or []

    print(f"  {c('URLhaus — Payload', BOLD, WHITE)}\n")
    print(f"  {'Famille / Signature':<26} {c(sig, RED, BOLD)}")
    print(f"  {'Type fichier':<26} {c(ftype, YELLOW)}")
    if fsz:
        print(f"  {'Taille':<26} {c(str(fsz) + ' bytes', DIM)}")
    if first:
        print(f"  {'Première observation':<26} {c(first, DIM)}")
    if last:
        print(f"  {'Dernière observation':<26} {c(last, DIM)}")
    if md5:
        print(f"  {'MD5':<26} {c(md5, DIM)}")
    if sha:
        print(f"  {'SHA256':<26} {c(sha, CYAN)}")
    if tags:
        print(f"  {'Tags':<26} " + "  ".join(c(f"[{t}]", CYAN) for t in tags))

    vt_info = data.get("virustotal") or {}
    if vt_info.get("result"):
        pct = vt_info.get("percent", "")
        col = RED if pct and float(pct) > 0 else DIM
        pct_s = f"  {c(f'({pct}%)', DIM)}" if pct else ""
        print(f"  {'VT (URLhaus)':<26} {c(vt_info['result'], col)}{pct_s}")

    if urls:
        print()
        n_on = len([u for u in urls if u.get("url_status") == "online"])
        col  = RED + BOLD if n_on > 0 else DIM
        print(f"  {c(f'Distribution — {len(urls)} URL(s)  |  {n_on} online', BOLD, WHITE)}\n")
        for u in urls[:10]:
            url_s  = u.get("url", "?")
            status = u.get("url_status", "?")
            added  = (u.get("date_added") or "")[:10]
            threat = u.get("threat") or ""
            is_on  = status == "online"
            dot    = c("●", RED + BOLD) if is_on else c("○", DIM)
            print(f"    {dot}  {c(url_s[:90], WHITE if is_on else DIM)}")
            meta   = [x for x in [threat, added] if x]
            if meta:
                print(f"       {c(' — '.join(meta), DIM)}")
        if len(urls) > 10:
            print(c(f"    … {len(urls) - 10} URL(s) supplémentaires", DIM))
    print()

def render_vt_hash_section(data: dict):
    """Affiche les détails VT pour un fichier/hash : stats, noms, type, dates,
    puis les 5 sections enrichies importées de virustotal_lookup :
    détections AV, YARA, Sigma, IDS crowdsourcés, et sandbox verdicts."""
    if not data or data.get("_skipped") or data.get("_error"):
        return
    attr = data.get("data", {}).get("attributes", {})
    sep()
    print(f"  {c('VirusTotal — Fichier', BOLD, WHITE)}\n")

    stats = attr.get("last_analysis_stats", {})
    mal   = stats.get("malicious", 0)
    sus   = stats.get("suspicious", 0)
    total = sum(stats.values())
    col   = RED + BOLD if mal > 0 else (YELLOW if sus > 0 else GREEN)

    names = (attr.get("names") or [])[:3]
    print(f"  {'Détections':<26} {c(f'{mal}', col)}/{total} moteurs"
          + (f"  {c(f'+{sus} suspects', YELLOW)}" if sus else ""))
    print(f"  {'Nom(s)':<26} {c(', '.join(names) or 'n/a', WHITE)}")
    print(f"  {'Type':<26} {c(attr.get('type_description', 'n/a'), DIM)}")
    size = attr.get("size")
    if size:
        print(f"  {'Taille':<26} {c(str(size) + ' bytes', DIM)}")

    for label, key in [("Première soumission", "first_submission_date"),
                        ("Dernière analyse",   "last_analysis_date")]:
        ts = attr.get(key)
        if ts:
            dt = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")
            print(f"  {label:<26} {c(dt, DIM)}")

    tags = attr.get("tags") or []
    if tags:
        print(f"  {'Tags':<26} " + "  ".join(c(f"[{t}]", CYAN) for t in tags))

    rep = attr.get("reputation")
    if rep is not None:
        print(f"  {'Réputation':<26} {c(rep, BOLD)}")

    votes = attr.get("total_votes") or {}
    if votes:
        print(f"  {'Votes communauté':<26} "
              f"{c('malveillant', RED)}:{votes.get('malicious', 0)}  "
              f"{c('clean', GREEN)}:{votes.get('harmless', 0)}")

    _vt_render_detections(attr.get("last_analysis_results", {}))
    _render_yara_rules(attr)
    _render_sigma_rules(attr)
    _render_crowdsourced_ids(attr)
    _render_sandbox_verdicts(attr)

def render_googledorks_section(data: dict, target: str):
    if not data:
        return
    if data.get("_error"):
        sep()
        print(f"  {c('Google Dorks', BOLD, WHITE)}")
        print(f"\n  {c('Erreur : ' + data['_error'][:120], RED)}\n")
        return
    if data.get("_skipped"):
        return
    from modules.googledorks_lookup import render as _gd_render
    _gd_render(target, data.get("items", []), total=data.get("total", ""))

def render_details(target, kind, results, years=None, as_json=False, show_offline=False):
    if as_json:
        print(json.dumps({"target": target, "type": kind, "results": results}, indent=2))
        return

    sep()
    print(f"  {c('Détails par source', BOLD)}\n")
    _render_mini_abuseipdb(results.get("abuseipdb"))
    _render_mini_virustotal(results.get("virustotal"))
    _render_mini_shodan(results.get("shodan"))
    _render_mini_censys(results.get("censys"))
    _render_mini_urlhaus(results.get("urlhaus"))
    print()

    # ── Services Censys ──
    render_censys_services(results.get("censys"))

    # ── Crowdsourced Context VT ──
    render_vt_crowdsourced_context(results.get("virustotal"))

    # ── Hashes URLhaus ──
    render_urlhaus_hashes(results.get("urlhaus"), show_offline=show_offline)

    # ── Communicating files VT ──
    comm = results.get("vt_communicating_files", {})
    if comm and not comm.get("error"):
        render_vt_file_section(
            comm.get("items", []), comm.get("count", 0),
            "VirusTotal — Communicating Files  (malicious ≥ 1)",
            years,
        )
    elif comm.get("error"):
        print(f"  {c('⚠', YELLOW)}  VT communicating files : {c(comm['error'], DIM)}")
        print()

    # ── Referrer files VT ──
    ref = results.get("vt_referrer_files", {})
    if ref and not ref.get("error"):
        render_vt_file_section(
            ref.get("items", []), ref.get("count", 0),
            "VirusTotal — Referrer Files  (malicious ≥ 1)",
            years,
        )
    elif ref.get("error"):
        print(f"  {c('⚠', YELLOW)}  VT referrer files : {c(ref['error'], DIM)}")
        print()

    # ── Erreurs (404/403 Shodan exclus — gérés inline) ──
    errors = {k: v for k, v in results.get("_errors", {}).items()
              if not (k == "shodan" and ("404" in str(v) or "403" in str(v)))}
    if errors:
        sep()
        print(f"  {c('Erreurs', DIM)}")
        for src, err in errors.items():
            print(f"    {c(src, DIM):<16}  {c(err, DIM)}")
        print()

    # ── Sources ignorées ──
    skipped = [s for s, d in results.items()
               if s not in ("_errors", "vt_communicating_files", "vt_referrer_files")
               and isinstance(d, dict) and d.get("_skipped")]
    if skipped:
        sep()
        print(f"  {c('Sources ignorées (clé manquante)', DIM)}")
        for src in skipped:
            svc_url = SERVICES.get(src, {}).get("url", "")
            print(f"    {c('·', DIM)}  {c(src, DIM):<16}  {c(svc_url, CYAN)}")
        print()
        print(f"  → Lance {c('python setup.py', CYAN)} pour configurer les clés manquantes.")
        print()

    sep("═")

# ── orchestration ──────────────────────────────────────────────────────────────

def run_correlation(target, keys, as_json=False, years=None, cache=None, show_offline=False,
                    quiet: bool = False):
    """Analyse principale pour une IP ou URL.
    Phase 1 : fetch en parallèle de toutes les sources applicables.
    Phase 1b : si URLhaus ne retourne pas de payloads inline, les récupère URL par URL.
    Phase 2 : fetch séquentiel des relations VT (communicating + referrer files) —
              séquentiel car le plan gratuit VT = 4 req/min ; on dort 16s entre chaque."""
    if cache is not None:
        hit = _cache_get(cache, _cache_key(target, years))
        if hit:
            kind = hit["type"]
            results = hit["results"]
            score, signals = score_from_results(results)
            if not as_json and not quiet:
                render_summary(target, results, score, signals, cached=True)
                render_details(target, kind, results, years=years, show_offline=show_offline)
            elif as_json:
                print(json.dumps({**hit, "cached": True}, indent=2))
            return hit

    kind  = "url" if is_url(target) else ("hash" if is_hash(target) else ("domain" if is_domain(target) else "ip"))
    tasks = {}

    if kind == "ip":
        tasks["abuseipdb"]  = (fetch_abuseipdb,     target, keys["abuseipdb"])
        tasks["virustotal"] = (fetch_virustotal_ip,  target, keys["virustotal"])
        tasks["shodan"]     = (fetch_shodan,         target, keys["shodan"])
        tasks["censys"]     = (fetch_censys,         target, keys["censys"])
        tasks["urlhaus"]    = (fetch_urlhaus_host,   target, keys["urlhaus"])
    elif kind == "url":
        host = extract_host_from_url(target)
        tasks["urlhaus"]    = (fetch_urlhaus_url,    target, keys["urlhaus"])
        tasks["virustotal"] = (fetch_virustotal_url, target, keys["virustotal"])
        if host:
            if is_ip(host):
                tasks["abuseipdb"] = (fetch_abuseipdb,    host, keys["abuseipdb"])
                tasks["shodan"]    = (fetch_shodan,        host, keys["shodan"])
            else:
                tasks["urlhaus_host"] = (fetch_urlhaus_host, host, keys["urlhaus"])
    elif kind == "domain":
        tasks["virustotal"] = (fetch_virustotal_domain, target, keys["virustotal"])
        tasks["urlhaus"]    = (fetch_urlhaus_host,       target, keys["urlhaus"])
    else:
        tasks["virustotal"] = (fetch_virustotal_url, target, keys["virustotal"])

    results = {}
    errors  = {}

    # Phase 1 : fetch en parallèle
    with ThreadPoolExecutor(max_workers=len(tasks)) as pool:
        futures = {
            pool.submit(safe_fetch, name, fn, *args): name
            for name, (fn, *args) in tasks.items()
        }
        for future in as_completed(futures):
            name, data, err = future.result()
            if err:
                errors[name] = err
                results[name] = {"_error": err}
            else:
                results[name] = data
    if errors:
        results["_errors"] = errors

    # Phase 1b : URLhaus — si payloads absent/null, requête chaque URL individuellement
    urlhaus_key  = keys.get("urlhaus", "")
    urlhaus_data = results.get("urlhaus", {})
    if (urlhaus_data
            and not urlhaus_data.get("_error")
            and not urlhaus_data.get("_skipped")
            and not urlhaus_data.get("payloads")):
        urls_list    = urlhaus_data.get("urls") or []
        targets_urls = [u.get("url") for u in urls_list if u.get("url")][:8]
        def _fetch_url_payload(url_str):
            try:
                return _urlhaus_post(
                    "https://urlhaus-api.abuse.ch/v1/url/",
                    {"url": url_str},
                    urlhaus_key,
                )
            except Exception:
                return {}

        collected = []
        seen      = set()
        if targets_urls:
            with ThreadPoolExecutor(max_workers=min(4, len(targets_urls))) as pool:
                for url_str, url_resp in zip(targets_urls, pool.map(_fetch_url_payload, targets_urls)):
                    for p in (url_resp.get("payloads") or []):
                        sha = p.get("response_sha256") or p.get("sha256") or ""
                        key = (sha, url_str)
                        if key not in seen:
                            seen.add(key)
                            collected.append({**p, "url": url_str,
                                              "_url_status": url_resp.get("url_status", "")})
        if collected:
            results["urlhaus"]["payloads"] = collected

    # Phase 2 : relationships VT (communicating + referrer files) — IP uniquement
    # 16s de délai avant chaque call : VT free tier = 4 req/min, les 2 calls
    # de la phase 1 (fetch_virustotal_ip) ont déjà consommé 1 requête.
    vt_key = keys.get("virustotal", "")
    vt_ok  = (vt_key
              and not results.get("virustotal", {}).get("_error")
              and not results.get("virustotal", {}).get("_skipped"))

    if kind == "ip" and vt_ok:
        for key_name, rel_path, label in [
            ("vt_communicating_files", f"/ip_addresses/{urllib.parse.quote(target, safe='')}/communicating_files", "communicating files"),
            ("vt_referrer_files",      f"/ip_addresses/{urllib.parse.quote(target, safe='')}/referrer_files",      "referrer files"),
        ]:
            print(c(f"  Fetch VT {label}...", DIM), end="\r", flush=True)
            time.sleep(16)
            try:
                items, count = _vt_relationship(rel_path, vt_key)
                filtered = filter_vt_files(items, years=years, min_malicious=1)
                results[key_name] = {"items": filtered, "count": count}
            except Exception as e:
                results[key_name] = {"error": str(e), "items": [], "count": 0}
        print(" " * 55, end="\r")

    score, signals = score_from_results(results)

    if not as_json and not quiet:
        render_summary(target, results, score, signals)
        render_details(target, kind, results, years=years, as_json=False, show_offline=show_offline)

    result = {"target": target, "type": kind, "score": score, "results": results}

    # Sauvegarde en cache — ignoré si la cible contient un espace (entrée malformée)
    if cache is not None and ' ' not in target:
        _cache_set(cache, _cache_key(target, years), result)
        _cache_save(cache)

    return result

# ── hash render ───────────────────────────────────────────────────────────────

def _render_hash_result(h: str, results: dict, score: int, signals: list, cached: bool = False):
    sep("═")
    cache_s = f"  {c('(cache)', DIM)}" if cached else ""
    print(f"\n  {c('IOC Hunting — Hash', BOLD, WHITE)}  {c('›', DIM)}  {c(h, CYAN, BOLD)}{cache_s}\n")
    level_label, level_col = threat_level(score)
    bar = c("█" * int(score / 5), level_col) + c("░" * (20 - int(score / 5)), DIM)
    print(f"  {c('Score de menace', BOLD)}  {bar}  {c(f'{score}/100', level_col, BOLD)}  [{level_label}]")
    print()
    if signals:
        print(f"  {c('Signaux détectés', BOLD)}")
        for s in signals:
            print(f"    {c('·', DIM)}  {s}")
    else:
        print(f"  {c('·  Aucun signal malveillant détecté', GREEN)}")
    print()
    sep()
    print(f"  {c('Détails par source', BOLD)}\n")
    _render_mini_vt_hash(results.get("virustotal"))
    _render_mini_urlhaus_hash(results.get("urlhaus"))
    print()
    render_urlhaus_hash_section(results.get("urlhaus", {}))
    render_vt_hash_section(results.get("virustotal", {}))
    if not cached:
        skipped = [s for s, d in results.items()
                   if s not in ("_errors",) and isinstance(d, dict) and d.get("_skipped")]
        if skipped:
            sep()
            print(f"  {c('Sources ignorées (clé manquante)', DIM)}")
            for src in skipped:
                svc_url = SERVICES.get(src, {}).get("url", "")
                print(f"    {c('·', DIM)}  {c(src, DIM):<16}  {c(svc_url, CYAN)}")
            print()
            print(f"  → Lance {c('python setup.py', CYAN)} pour configurer les clés manquantes.")
            print()
    sep("═")

# ── hash correlation ───────────────────────────────────────────────────────────

def run_hash_correlation(targets: list, keys: dict, as_json: bool = False, export_path: str = None, cache: dict = None, quiet: bool = False) -> list:
    """Analyse une liste de hashes (MD5/SHA1/SHA256) via VT + URLhaus en parallèle.
    16s de pause entre chaque hash pour respecter le rate limit VT (4 req/min).
    Retourne la liste de tous les résultats ; exporte en JSON si export_path fourni."""
    all_results = []
    _n = len(targets)
    for i, h in enumerate(targets):
        if _n > 1 and not as_json and not quiet:
            _show_progress(i + 1, _n, h[:20] + ("…" if len(h) > 20 else ""))
        # Vérifie le cache avant toute requête API
        if cache is not None:
            hit = _cache_get(cache, h)
            if hit:
                score, signals = score_from_hash_results(hit["results"])
                if not as_json and not quiet:
                    _render_hash_result(h, hit["results"], score, signals, cached=True)
                elif as_json:
                    print(json.dumps({**hit, "cached": True}, indent=2))
                all_results.append(hit)
                continue  # passe au hash suivant sans dormir

        if i > 0:
            time.sleep(16)  # VT free tier : 4 req/min

        results = {}
        errors  = {}
        tasks   = {
            "virustotal": (fetch_virustotal_hash, h, keys["virustotal"]),
            "urlhaus":    (fetch_urlhaus_hash,    h, keys["urlhaus"]),
        }
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = {
                pool.submit(safe_fetch, name, fn, *args): name
                for name, (fn, *args) in tasks.items()
            }
            for future in as_completed(futures):
                name, data, err = future.result()
                if err:
                    errors[name] = err
                    results[name] = {"_error": err}
                else:
                    results[name] = data
        if errors:
            results["_errors"] = errors

        score, signals = score_from_hash_results(results)

        if not as_json and not quiet:
            _render_hash_result(h, results, score, signals, cached=False)
        elif as_json:
            print(json.dumps({"target": h, "type": "hash", "score": score, "results": results}, indent=2))

        result = {"target": h, "type": "hash", "score": score, "results": results}

        # Sauvegarde en cache — ignoré si le hash contient un espace (entrée malformée)
        if cache is not None and ' ' not in h:
            _cache_set(cache, h, result)
            _cache_save(cache)

        all_results.append(result)

    if _n > 1 and not as_json and not quiet:
        _clear_progress()

    if export_path:
        with open(export_path, "w") as fh:
            json.dump(all_results, fh, indent=2)
        if not quiet:
            print(c(f"\n  Rapport exporté → {export_path}", GREEN))

    return all_results

# ── barre de progression ───────────────────────────────────────────────────────

def _show_progress(current: int, total: int, label: str):
    """Affiche une barre de progression collée en bas du terminal visible.
    Utilise save/restore cursor pour ne pas perturber la sortie normale."""
    try:
        size   = shutil.get_terminal_size()
        cols   = size.columns
        rows   = size.lines
        bar_w  = 20
        filled = int(bar_w * current / total)
        bar    = ("\033[96m" + "█" * filled
                  + "\033[0m\033[2m" + "░" * (bar_w - filled) + "\033[0m")
        prefix = f"  [{current}/{total}]  "
        max_lbl = max(0, cols - len(prefix) - bar_w - 4)
        lbl  = label[:max_lbl] if max_lbl else ""
        line = f"\033[2m{prefix}\033[0m{bar}\033[2m  {lbl}\033[0m"
        sys.stdout.write(f"\033[s\033[{rows};0H\033[K{line}\033[u")
        sys.stdout.flush()
    except Exception:
        pass

def _clear_progress():
    """Efface la barre de progression."""
    try:
        rows = shutil.get_terminal_size().lines
        sys.stdout.write(f"\033[s\033[{rows};0H\033[K\033[u")
        sys.stdout.flush()
    except Exception:
        pass

# ── helpers export ─────────────────────────────────────────────────────────────

def _threat_level_plain(score: int) -> str:
    if score >= 70: return "CRITIQUE"
    if score >= 40: return "ÉLEVÉ"
    if score >= 15: return "MODÉRÉ"
    return "FAIBLE"

def _export_csv(all_results: list, path: str):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow([
            "target", "type", "score", "level",
            "vt_malicious", "vt_suspicious",
            "abuseipdb_score", "urlhaus_status", "shodan_cves",
        ])
        for r in all_results:
            res    = r.get("results", {})
            score  = r.get("score", 0)
            stats  = (res.get("virustotal", {})
                        .get("data", {})
                        .get("attributes", {})
                        .get("last_analysis_stats", {}))
            shodan = res.get("shodan", {})
            cves   = (len(shodan.get("vulns") or [])
                      if shodan and not shodan.get("_skipped") and not shodan.get("_error") else "")
            writer.writerow([
                r.get("target", ""),
                r.get("type", ""),
                score,
                _threat_level_plain(score),
                stats.get("malicious", ""),
                stats.get("suspicious", ""),
                (res.get("abuseipdb", {})
                    .get("data", {})
                    .get("abuseConfidenceScore", "")),
                res.get("urlhaus", {}).get("query_status", ""),
                cves,
            ])

# ── helpers menu interactif ────────────────────────────────────────────────────

def _sha256_file(path: str) -> str:
    """Calcule le SHA256 d'un fichier en chunks de 64KB pour éviter de tout charger en RAM."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def _collect_files(path: str) -> list:
    """Retourne la liste des fichiers à analyser : le fichier lui-même, ou tous les
    fichiers directs d'un répertoire (non-récursif, exclut les sous-répertoires)."""
    p = os.path.abspath(path)
    if os.path.isfile(p):
        return [p]
    if os.path.isdir(p):
        files = sorted(
            os.path.join(p, f)
            for f in os.listdir(p)
            if os.path.isfile(os.path.join(p, f))
        )
        return files
    return []

def _hash_files(file_paths: list) -> list:
    """
    Calcule le SHA256 de chaque fichier.
    Retourne une liste de (sha256, chemin_court, taille_bytes).
    """
    results = []
    for fp in file_paths:
        try:
            sha = _sha256_file(fp)
            size = os.path.getsize(fp)
            results.append((sha, fp, size))
        except Exception as e:
            print(c(f"  Impossible de hasher {fp} : {e}", YELLOW))
    return results

def _ask_ip_targets_interactive():
    """Saisie interactive des cibles IP/URL.
    Option 1 : saisie directe ligne par ligne.
    Option 2 : fichier texte ou répertoire (toutes les lignes qui ressemblent à une IP ou URL).
    Option r : retour → retourne None (sentinel "retour au menu principal").
    Retourne [] si rien de valide trouvé (pas None — None = retour explicite)."""
    print(c("  1  Saisie directe de l'IP / URL / Domaine", WHITE))
    print(c("  2  Charger depuis un fichier ou répertoire", WHITE))
    print(c("  r  Retour au menu principal", WHITE))
    method = input(c("  Choix › ", CYAN)).strip().lower()

    if method == "r":
        return None

    if method == "2":
        path = _input_path(c("  Chemin (fichier ou répertoire) › ", CYAN))
        p = os.path.abspath(path)
        if not os.path.exists(p):
            print(c(f"  Chemin introuvable : {path}", RED))
            return []

        # Répertoire → scan de tous les fichiers texte
        if os.path.isdir(p):
            files = sorted(
                os.path.join(p, f) for f in os.listdir(p)
                if os.path.isfile(os.path.join(p, f))
            )
            if not files:
                print(c("  Répertoire vide.", DIM))
                return []
            print(c(f"  Répertoire détecté — lecture de {len(files)} fichier(s)...", DIM))
            raw = []
            for fp in files:
                try:
                    with open(fp, errors="replace") as fh:
                        raw += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
                except Exception:
                    pass
        else:
            try:
                with open(p, errors="replace") as fh:
                    raw = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
            except Exception as e:
                print(c(f"  Erreur de lecture : {e}", RED))
                return []

        targets = [l for l in raw if is_ip(l) or is_url(l) or is_domain(l)]
        skipped = len(raw) - len(targets)
        if skipped:
            print(c(f"  {skipped} ligne(s) ignorée(s) (ni IP, domaine ni URL valide).", YELLOW))
        if not targets:
            print(c("  Aucune IP / domaine / URL valide trouvée.", RED))
            return []
        print(c(f"  {len(targets)} cible(s) chargée(s).", GREEN))
        return targets

    else:
        print(c("  Entre les IPs / URLs / Domaines une par ligne. Ligne vide pour terminer.", DIM))
        targets = []
        while True:
            line = input(c("  › ", DIM)).strip()
            if not line:
                break
            if ' ' in line:
                parts = line.split()
                if all(is_ip(p) or is_url(p) or is_hash(p) or is_domain(p) for p in parts):
                    print(c(f"  Une seule cible par ligne — entre chaque IP / URL / Domaine séparément.", YELLOW))
                    continue
            targets.append(line)
        return targets

def _ask_hash_targets_interactive():
    """Saisie interactive des cibles hash.
    Option 1 : saisie directe (MD5/SHA1/SHA256), validation format par is_hash().
    Option 2 : chemin vers un fichier ou répertoire → calcul SHA256 local des fichiers,
               affichage d'un tableau de prévisualisation avant confirmation.
    Option r : retour → retourne None.
    Retourne une liste de SHA256 hex strings."""
    print(c("  1  Saisie directe du hash  (MD5 / SHA256)", WHITE))
    print(c("  2  Hasher un fichier ou un répertoire", WHITE))
    print(c("  r  Retour au menu principal", WHITE))
    method = input(c("  Choix › ", CYAN)).strip().lower()

    if method == "r":
        return None

    if method == "2":
        path = _input_path(c("  Chemin (fichier ou répertoire) › ", CYAN))
        files = _collect_files(path)
        if not files:
            if not os.path.exists(os.path.abspath(path)):
                print(c(f"  Chemin introuvable : {path}", RED))
            else:
                print(c("  Aucun fichier trouvé.", DIM))
            return []

        src = "répertoire" if os.path.isdir(os.path.abspath(path)) else "fichier"
        print(c(f"  {src.capitalize()} détecté — calcul SHA256 de {len(files)} fichier(s)...", DIM))
        hashed = _hash_files(files)
        if not hashed:
            return []

        print()
        for sha, fp, size in hashed:
            name = os.path.basename(fp)
            kb   = size / 1024
            sz_s = f"{kb:.1f} KB" if kb < 1024 else f"{kb/1024:.1f} MB"
            print(f"  {c('►', CYAN)}  {c(name, WHITE):<40}  {c(sha[:16] + '…', DIM)}  {c(sz_s, DIM)}")
        print()

        try:
            ok = input(c(f"  Lancer l'analyse pour ces {len(hashed)} hash(es) ? (O/n) › ", DIM)).strip().lower()
        except EOFError:
            print(); return []
        if ok == "n":
            return []
        return [sha for sha, _, _ in hashed]

    else:
        print(c("  Entre les hashes un par ligne. Ligne vide pour terminer.", DIM))
        targets = []
        while True:
            line = input(c("  › ", DIM)).strip()
            if not line:
                break
            if not is_hash(line):
                print(c(f"  Format invalide (attendu MD5 ou SHA256) : {line[:40]}", YELLOW))
                continue
            targets.append(line)
        return targets

def _launch_web(keys: dict, cache):
    """Lance le serveur Flask local. Appelé depuis --web et depuis le menu interactif."""
    from modules.web_server import create_app, is_port_available
    default_port = int(load_setting("web_port") or 5000)
    while True:
        try:
            raw = input(c(f"  Port  ({default_port} par défaut) › ", CYAN)).strip()
        except EOFError:
            raw = ""
        port = int(raw) if raw.isdigit() else default_port
        if not (1024 <= port <= 65535):
            print(c("  Port invalide — choisis entre 1024 et 65535.", RED))
            continue
        if not is_port_available(port):
            print(c(f"  Port {port} déjà utilisé, choisis-en un autre.", RED))
            continue
        break
    app = create_app(keys, cache, {
        'correlation': run_correlation,
        'hash':        run_hash_correlation,
        'is_hash':     is_hash,
        'parse_years': parse_years,
    }, port)
    print(c(f"\n  Interface web disponible sur ", DIM) + c(f"http://127.0.0.1:{port}", CYAN, BOLD))
    print(c("  Ctrl+C pour arrêter.\n", DIM))
    import logging
    logging.getLogger('werkzeug').setLevel(logging.ERROR)
    app.run(host='127.0.0.1', port=port, debug=False)


def _run_ip_interactive(keys: dict, years, cache=None, show_offline=False):
    """Session interactive IP/URL : appelle _ask_ip_targets_interactive(),
    puis run_correlation() pour chaque cible. Retourne sans action si "retour"."""
    print()
    targets = _ask_ip_targets_interactive()
    if targets is None:   # retour demandé
        return
    if not targets:
        return
    yr_in = input(c("  Filtrer VT files par année(s) ? ex: 2025  (vide = tout) › ", DIM)).strip()
    if yr_in:
        years = parse_years(yr_in)
    export = _input_path(c("  Fichier export JSON (vide = pas d'export) › ", DIM)) or None
    missing = [svc for svc, k in keys.items() if not k]
    if missing:
        print(c(f"\n  Clés manquantes : {', '.join(missing)}", YELLOW))
        print(f"  Lance {c('python setup.py', CYAN)} pour les configurer.\n")
    if years:
        print(c(f"  Filtre années VT : {', '.join(str(y) for y in sorted(years))}", DIM))
        print()
    serpapi_key = keys.get("serpapi", "")
    use_dorks = False
    if serpapi_key:
        try:
            dorks_ans = input(c("  Lancer Google Dorks pour chaque cible ? (o/N) › ", DIM)).strip().lower()
        except EOFError:
            dorks_ans = "n"
        use_dorks = (dorks_ans == "o")
    all_results = []
    for target in targets:
        r = run_correlation(target, keys, years=years, cache=cache, show_offline=show_offline)
        all_results.append(r)
        if use_dorks:
            print(c("  Recherche Google Dorks...", DIM), end="\r", flush=True)
            gd_data = fetch_googledorks(target, serpapi_key)
            print(" " * 40, end="\r")
            render_googledorks_section(gd_data, target)
    if export:
        with open(export, "w") as fh:
            json.dump(all_results, fh, indent=2)
        print(c(f"  Rapport exporté → {export}", GREEN))

def _run_hash_interactive(keys: dict, cache=None):
    """Boucle interactive hash : demande des cibles, lance run_hash_correlation(),
    puis propose d'analyser un autre hash ou de revenir au menu principal."""
    missing = [s for s, k in keys.items() if not k and s in ("virustotal", "urlhaus")]
    if missing:
        print(c(f"\n  Clés manquantes : {', '.join(missing)}", YELLOW))
        print(f"  Lance {c('python setup.py', CYAN)} pour les configurer.\n")

    while True:
        print()
        targets = _ask_hash_targets_interactive()
        if targets is None:   # retour au menu principal
            return
        if not targets:
            try:
                retry = input(c("  Réessayer ? (O/n) › ", DIM)).strip().lower()
            except EOFError:
                print(); break
            if retry != "n":
                continue
            break
        export = _input_path(c("  Fichier export JSON (vide = pas d'export) › ", DIM)) or None
        run_hash_correlation(targets, keys, export_path=export, cache=cache)

        print()
        try:
            again = input(c("  Analyser un autre hash ? (O/n) › ", DIM)).strip().lower()
        except EOFError:
            print(); break
        if again == "n":
            break

# ── main ──────────────────────────────────────────────────────────────────────

def main():
    """Point d'entrée. Flux de décision :
    1. Si --type hash ou toutes les cibles sont des hashes → run_hash_correlation()
    2. Si des cibles sont fournies → run_correlation() pour chaque, puis boucle "analyser autre ?"
    3. Sinon → menu interactif (choix 1=IP/URL, 2=Hash, q=quitter)
    """
    parser = argparse.ArgumentParser(
        prog="main",
        description="IOC Hunting — corrélation multi-sources (IP/URL ou Hash)",
    )
    parser.add_argument("targets", nargs="*", help="IPs, URLs ou hashes")
    parser.add_argument("--file",   "-f",  help="Fichier de cibles (une par ligne) ; - pour stdin")
    parser.add_argument("--json",          action="store_true", help="Sortie JSON brute")
    parser.add_argument("--export", "-e",  help="Exporter rapport (JSON ou CSV selon l'extension .csv)")
    parser.add_argument("--year",   "-y",  help="Filtrer VT files par année(s) ex: 2025  ou  2024,2025")
    parser.add_argument("--type",    "-t",  choices=["ip", "hash"],
                        help="Mode d'analyse : ip (multi-sources) ou hash (VT + URLhaus)")
    parser.add_argument("--nocache", action="store_true",
                        help="Ignore le cache et force les requêtes API")
    parser.add_argument("--offline", action="store_true",
                        help="Affiche aussi les payloads URLhaus offline")
    parser.add_argument("--quiet",   "-q", action="store_true",
                        help="Supprime toute sortie. Code retour 1 si score ≥ seuil (--threshold).")
    parser.add_argument("--threshold",     type=int, default=40, metavar="N",
                        help="Seuil de score pour --quiet (défaut: 40)")
    parser.add_argument("--web", "-w", action="store_true",
                        help="Lance l'interface web locale (127.0.0.1)")
    args = parser.parse_args()

    years = parse_years(args.year) if args.year else None

    targets = list(args.targets)
    if args.file:
        if args.file == "-":
            targets += [l.strip() for l in sys.stdin if l.strip() and not l.startswith("#")]
        else:
            try:
                with open(args.file) as fh:
                    targets += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
            except FileNotFoundError:
                print(c(f"Fichier introuvable : {args.file}", RED), file=sys.stderr)
                sys.exit(1)

    # Déduplication — préserve l'ordre d'apparition
    n_before = len(targets)
    targets  = list(dict.fromkeys(targets))
    if n_before > len(targets) and not args.json and not args.quiet:
        print(c(f"  {n_before - len(targets)} doublon(s) supprimé(s).", DIM))

    keys = all_keys()

    # Charge le TTL depuis settings.json (sans passphrase) — fallback 24h si absent
    global _CACHE_TTL
    _CACHE_TTL = int(load_setting("cache_ttl") or 86400)

    # Charge le cache et purge les entrées expirées selon _CACHE_TTL
    # --nocache désactive complètement le cache pour cette session
    cache = None
    if not args.nocache:
        cache = _cache_load()
        n_expired = _cache_purge(cache)
        if n_expired and not args.json:
            print(c(f"  {n_expired} entrée(s) expirée(s) supprimée(s) du cache.", DIM))
        # Avertissement si le cache dépasse _CACHE_MAX entrées (seuil : ~10 MB)
        # En mode JSON/non-interactif on ne bloque pas, on continue silencieusement
        if len(cache) > _CACHE_MAX and not args.json:
            print(c(f"  Cache : {len(cache)} entrées (limite recommandée : {_CACHE_MAX}).", YELLOW))
            try:
                ans = input(c("  Vider le cache maintenant ? (o/N) › ", DIM)).strip().lower()
            except EOFError:
                ans = "n"
            if ans == "o":
                cache.clear()
                _cache_save(cache)
                print(c("  Cache vidé.", GREEN))

    # ── Mode web ─────────────────────────────────────────────────────────────
    if args.web:
        _launch_web(keys, cache)
        return

    # ── Mode hash (--type hash ou auto-détection) ────────────────────────────
    force_hash = args.type == "hash"
    force_ip   = args.type == "ip"
    auto_hash  = (not force_ip and targets
                  and all(is_hash(t) for t in targets))

    if force_hash or auto_hash:
        if not targets:
            h = input(c("  Hash (MD5 / SHA256) › ", CYAN)).strip()
            if not h:
                sys.exit(0)
            targets = [h]
        if not args.json and not args.quiet:
            n = len(targets)
            label = f"{n} hash{'es' if n > 1 else ''} détecté{'s' if n > 1 else ''}"
            print(c(f"\n  {label}  →  VirusTotal · URLhaus\n", DIM))
        missing = [s for s, k in keys.items() if not k and s in ("virustotal", "urlhaus")]
        if missing and not args.json and not args.quiet:
            print(c(f"  Clés manquantes : {', '.join(missing)}", YELLOW))
            print(f"  Lance {c('python setup.py', CYAN)} pour les configurer.\n")
        json_export = args.export if args.export and not args.export.lower().endswith(".csv") else None
        all_results = run_hash_correlation(targets, keys, as_json=args.json,
                                           export_path=json_export, cache=cache, quiet=args.quiet)
        if args.export and args.export.lower().endswith(".csv"):
            _export_csv(all_results, args.export)
            if not args.quiet:
                print(c(f"  Rapport CSV exporté → {args.export}", GREEN))
        if args.quiet:
            sys.exit(1 if any(r.get("score", 0) >= args.threshold for r in all_results) else 0)
        return

    # ── Mode IP/URL/Domaine avec cibles fournies ─────────────────────────────
    if targets:
        if not args.json and not args.quiet:
            def _kind_label(t):
                if is_hash(t):    return "Hash"
                if is_url(t):     return "URL"
                if is_domain(t):  return "Domaine"
                return "IP"
            kinds   = sorted({_kind_label(t) for t in targets})
            n       = len(targets)
            kinds_s = "/".join(kinds)
            count_s = f"{n} cible{'s' if n > 1 else ''}" if n > 1 else targets[0]
            sources = "AbuseIPDB · VT · Shodan · Censys · URLhaus"
            print(c(f"\n  {kinds_s} détecté{'e' if any(k in kinds for k in ('IP', 'URL', 'Domaine')) else ''}"
                    f"{'' if n == 1 else f' ({count_s})'}  →  {sources}\n", DIM))
        missing = [svc for svc, k in keys.items() if not k]
        if missing and not args.json and not args.quiet:
            print()
            print(c(f"  Clés manquantes : {', '.join(missing)}", YELLOW))
            print(f"  Lance {c('python setup.py', CYAN)} pour les configurer.\n")
        if years and not args.json and not args.quiet:
            print(c(f"  Filtre années VT : {', '.join(str(y) for y in sorted(years))}", DIM))
            print()
        all_results = []
        _n = len(targets)
        for _i, target in enumerate(targets):
            if _n > 1 and not args.json and not args.quiet:
                _show_progress(_i + 1, _n, target)
            r = run_correlation(target, keys, as_json=args.json, years=years, cache=cache,
                                show_offline=args.offline, quiet=args.quiet)
            all_results.append(r)
        if _n > 1 and not args.json and not args.quiet:
            _clear_progress()
        if args.export:
            if args.export.lower().endswith(".csv"):
                _export_csv(all_results, args.export)
                if not args.quiet:
                    print(c(f"  Rapport CSV exporté → {args.export}", GREEN))
            else:
                with open(args.export, "w") as fh:
                    json.dump(all_results, fh, indent=2)
                if not args.quiet:
                    print(c(f"  Rapport exporté → {args.export}", GREEN))
        if not args.json and not args.quiet:
            while True:
                print()
                try:
                    nxt = input(c("  Analyser une autre cible ? (IP / URL / Domaine / hash  ou  Entrée pour quitter) › ", DIM)).strip()
                except EOFError:
                    print(); break
                if not nxt:
                    break
                r = run_correlation(nxt, keys, as_json=False, years=years, cache=cache,
                                    show_offline=args.offline)
                all_results.append(r)
                if args.export:
                    if args.export.lower().endswith(".csv"):
                        _export_csv(all_results, args.export)
                        print(c(f"  Rapport CSV mis à jour → {args.export}", GREEN))
                    else:
                        with open(args.export, "w") as fh:
                            json.dump(all_results, fh, indent=2)
                        print(c(f"  Rapport mis à jour → {args.export}", GREEN))
        if args.quiet:
            sys.exit(1 if any(r.get("score", 0) >= args.threshold for r in all_results) else 0)
        return

    # ── Menu interactif (aucune cible, aucun --type) ─────────────────────────
    def _print_main_menu():
        print()
        print(c("  ╔═════════════════════════════════════════════════════╗", CYAN))
        print(c("  ║  ", CYAN) + c("IOC Hunting", BOLD, WHITE) + c(" — Choix du mode d'analyse         ║", CYAN))
        print(c("  ╚═════════════════════════════════════════════════════╝", CYAN))
        print()
        print(f"  {c('1', BOLD)}  Analyser une IP / URL / Domaine   "
              f"{c('(AbuseIPDB · VT · Shodan · Censys · URLhaus)', DIM)}")
        print(f"  {c('2', BOLD)}  Analyser un hash         "
              f"{c('(VirusTotal · URLhaus)', DIM)}")
        print(f"  {c('w', BOLD)}  Interface web            "
              f"{c('(navigateur · 127.0.0.1)', DIM)}")
        print(f"  {c('q', BOLD)}  Quitter")
        print()

    _print_main_menu()
    while True:
        try:
            choix = input(c("  Choix › ", CYAN)).strip().lower()
        except EOFError:
            print(); sys.exit(0)

        if choix == "q":
            print(c("  Au revoir.\n", DIM)); sys.exit(0)
        elif choix == "1":
            _run_ip_interactive(keys, years, cache, show_offline=args.offline)
            _print_main_menu()
        elif choix == "2":
            _run_hash_interactive(keys, cache)
            _print_main_menu()
        elif choix == "w":
            _launch_web(keys, cache)
            _print_main_menu()
        else:
            print(c("  Choix invalide (1, 2, w ou q).", DIM))

if __name__ == "__main__":
    # Handler global Ctrl+C : toutes les fonctions internes attrapent seulement EOFError,
    # pas KeyboardInterrupt, pour que celui-ci remonte ici et affiche un message propre.
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {c('Ctrl+C détecté — Au revoir.', YELLOW)}\n")
        sys.exit(0)

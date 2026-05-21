#!/usr/bin/env python3
# Made by hsa5
"""
VirusTotal Lookup CLI (API v3, gratuit)
=======================================
Script standalone ET module importable par main.py.

Quand importé par main.py, les fonctions suivantes sont utilisées :
  vt_get, vt_get_retry        → HTTP helpers réutilisés pour les calls IP/URL/hash
  _render_detections          → détections AV (malicious + suspicious)
  _render_yara_rules          → YARA rules crowdsourcées
  _render_sigma_rules         → Sigma rules crowdsourcées
  _render_crowdsourced_ids    → IDS rules crowdsourcées
  _render_sandbox_verdicts    → verdicts Dynamic Analysis Sandbox

Usage standalone :
  python virustotal_lookup.py <ip|url|hash> [...]
  python virustotal_lookup.py --file targets.txt --full --export out.json
  python virustotal_lookup.py                  ← menu interactif

Clé API gratuite (500 req/jour, 4 req/min) : https://www.virustotal.com/gui/my-apikey
Configurée via setup.py ou variable d'env   : export VIRUSTOTAL_API_KEY="ta_clé"

Flag --full : ajoute communicating files, referrer files, resolutions, SSL, URLs associées.
              Chaque call relationship consomme 1 requête API (patience sur le plan gratuit).
"""

import sys
import os
import json
import argparse
import base64
import re
import time
import urllib.request
import urllib.parse
import urllib.error

import sys as _sys, os as _os
_path = _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), ".internal")
if _path not in _sys.path:
    _sys.path.insert(0, _path)
from config_loader import load_key, save_key_to_config

RESET   = "\033[0m";  BOLD  = "\033[1m";  DIM  = "\033[2m"
RED     = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
CYAN    = "\033[96m"; WHITE = "\033[97m"; MAGENTA = "\033[95m"

VT_BASE = "https://www.virustotal.com/api/v3"

def c(text, *codes): return "".join(codes) + str(text) + RESET
def sep(ch="─", w=72): print(c(ch * w, DIM))

RE_IP   = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
RE_HASH = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")

def detect_type(target):
    if RE_IP.match(target):   return "ip"
    if RE_HASH.match(target): return "hash"
    return "url"

# ── API key ────────────────────────────────────────────────────────────────────

def get_api_key(provided=None):
    if provided:
        return provided
    key = load_key("virustotal")
    if key:
        return key
    print()
    print(c("  Clé API VirusTotal requise.", YELLOW, BOLD))
    print(f"  Obtiens-en une sur {c('https://www.virustotal.com/gui/my-apikey', CYAN)}")
    print(f"  Ou lance {c('python setup.py', CYAN)} pour tout configurer.")
    print()
    key = input(c("  Colle ta clé API › ", CYAN)).strip()
    if not key:
        print(c("  Aucune clé fournie, abandon.", RED)); sys.exit(1)
    if input(c("  Sauvegarder ? (O/n) › ", DIM)).strip().lower() != "n":
        save_key_to_config("virustotal", key)
    return key

# ── HTTP helpers ───────────────────────────────────────────────────────────────

def _parse_body(raw: bytes, path: str) -> dict:
    """Parse JSON body — lève une ValueError claire si vide ou non-JSON."""
    if not raw or not raw.strip():
        raise ValueError(
            f"Réponse vide de VirusTotal ({path}).\n"
            "  Causes possibles : clé API invalide, rate limit, problème réseau.\n"
            "  Vérifie ta clé sur https://www.virustotal.com/gui/my-apikey"
        )
    try:
        return json.loads(raw.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as e:
        preview = raw[:120].decode("utf-8", errors="replace").replace("\n", " ")
        raise ValueError(f"Réponse non-JSON de VirusTotal : {preview!r}") from e

def _vt_error_msg(http_err: urllib.error.HTTPError) -> str:
    """Extrait le message d'erreur JSON de l'API VT depuis une HTTPError."""
    try:
        body = http_err.read().decode("utf-8", errors="replace")
        d    = json.loads(body)
        return d.get("error", {}).get("message") or f"HTTP {http_err.code}"
    except Exception:
        return f"HTTP {http_err.code}"

def vt_get(path: str, api_key: str) -> dict:
    req = urllib.request.Request(f"{VT_BASE}{path}")
    req.add_header("x-apikey", api_key)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return _parse_body(resp.read(), path)
    except urllib.error.HTTPError as e:
        msg = _vt_error_msg(e)
        raise urllib.error.HTTPError(e.url, e.code, msg, e.headers, None)

def vt_post(path: str, api_key: str, form_data: dict) -> dict:
    data = urllib.parse.urlencode(form_data).encode()
    req  = urllib.request.Request(f"{VT_BASE}{path}", data=data, method="POST")
    req.add_header("x-apikey", api_key)
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return _parse_body(resp.read(), path)
    except urllib.error.HTTPError as e:
        msg = _vt_error_msg(e)
        raise urllib.error.HTTPError(e.url, e.code, msg, e.headers, None)

def vt_get_retry(path: str, api_key: str, label: str = "") -> dict:
    """Appel GET avec retry exponentiel sur 429 (rate limit VT free tier : 4 req/min).
    Attend 16s, 32s, 48s, 64s entre chaque tentative. Lève RuntimeError après 4 échecs."""
    for attempt in range(4):
        try:
            return vt_get(path, api_key)
        except urllib.error.HTTPError as e:
            if e.code == 429:
                wait = 16 * (attempt + 1)
                print(c(f"  Rate limit (429) {label}— attente {wait}s...", YELLOW), end="\r", flush=True)
                time.sleep(wait)
                continue
            raise
    raise RuntimeError(f"Rate limit persistant après 4 tentatives ({path})")

# ── relationship fetcher ───────────────────────────────────────────────────────

def vt_relationship(base_path: str, rel: str, api_key: str, limit: int = 10) -> tuple[list, int]:
    """Récupère une relation VT (communicating_files, resolutions, etc.).
    404 → liste vide sans erreur (normal pour les IPs peu connues).
    Retourne (liste d'items, count total)."""
    path = f"{base_path}/{rel}?limit={limit}"
    try:
        data = vt_get_retry(path, api_key, label=f"[{rel}] ")
        return data.get("data", []), data.get("meta", {}).get("count", 0)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return [], 0
        raise

# ── query functions ────────────────────────────────────────────────────────────

def query_ip(ip: str, api_key: str, full: bool = False) -> dict:
    result = {"main": vt_get_retry(f"/ip_addresses/{ip}", api_key)}
    if not full:
        return result

    rels = [
        ("communicating_files",        "Communicating files"),
        ("referrer_files",             "Referrer files"),
        ("urls",                       "URLs associées"),
        ("resolutions",                "Résolutions DNS"),
        ("historical_ssl_certificates","Certificats SSL"),
    ]
    for rel, label in rels:
        print(c(f"  Fetch {label}...", DIM), end="\r", flush=True)
        try:
            items, count = vt_relationship(f"/ip_addresses/{ip}", rel, api_key)
            result[rel] = {"items": items, "count": count}
        except Exception as e:
            result[rel] = {"error": str(e), "items": [], "count": 0}
    print(" " * 50, end="\r")  # efface la ligne de progression
    return result

def query_url(url_target: str, api_key: str, full: bool = False) -> dict:
    url_id = base64.urlsafe_b64encode(url_target.encode()).rstrip(b"=").decode()
    try:
        main = vt_get_retry(f"/urls/{url_id}", api_key)
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise
        # Soumettre l'URL pour analyse
        sub = vt_post("/urls", api_key, {"url": url_target})
        analysis_id = sub.get("data", {}).get("id", "")
        if not analysis_id:
            return {"main": {"_error": "Soumission échouée"}}
        print(c("  URL soumise — attente analyse (jusqu'à 30s)...", DIM), end="\r", flush=True)
        for _ in range(6):
            time.sleep(5)
            try:
                an = vt_get(f"/analyses/{analysis_id}", api_key)
                if an.get("data", {}).get("attributes", {}).get("status") == "completed":
                    main = vt_get_retry(f"/urls/{url_id}", api_key)
                    break
            except Exception:
                pass
        else:
            return {"main": {"_error": "Analyse non terminée dans le délai imparti"}}
        print(" " * 55, end="\r")

    result = {"main": main}
    if not full:
        return result

    rels = [
        ("contacted_ips",     "Contacted IPs"),
        ("contacted_domains", "Contacted domains"),
        ("downloaded_files",  "Downloaded files"),
        ("redirecting_urls",  "Redirecting URLs"),
    ]
    for rel, label in rels:
        print(c(f"  Fetch {label}...", DIM), end="\r", flush=True)
        try:
            items, count = vt_relationship(f"/urls/{url_id}", rel, api_key)
            result[rel] = {"items": items, "count": count}
        except Exception as e:
            result[rel] = {"error": str(e), "items": [], "count": 0}
    print(" " * 50, end="\r")
    return result

def query_hash(h: str, api_key: str) -> dict:
    return {"main": vt_get_retry(f"/files/{h}", api_key)}

def query_vt(target: str, api_key: str, full: bool = False) -> tuple[str, dict]:
    kind = detect_type(target)
    if kind == "ip":   return "ip",   query_ip(target, api_key, full=full)
    if kind == "hash": return "hash", query_hash(target, api_key)
    return "url", query_url(target, api_key, full=full)

# ── render helpers ─────────────────────────────────────────────────────────────

def _stats_line(stats: dict) -> str:
    mal   = stats.get("malicious", 0)
    sus   = stats.get("suspicious", 0)
    total = sum(stats.values())
    col   = RED + BOLD if mal > 0 else (YELLOW if sus > 0 else GREEN)
    suffix = c(f"  (+{sus} suspects)", YELLOW) if sus else ""
    return c(f"{mal}", col) + c(f"/{total} moteurs", DIM) + suffix

def _render_detections(results: dict, limit: int = 20):
    """Affiche les détections AV depuis last_analysis_results.
    Séparé en deux listes pour éviter deux passes sur le dict — single-pass via append.
    Affiche max limit moteurs malicious + 5 suspects."""
    positives  = []
    suspicious = []
    for eng, r in results.items():
        cat = r.get("category")
        if cat == "malicious":
            positives.append((eng, r))
        elif cat == "suspicious":
            suspicious.append((eng, r))
    if positives or suspicious:
        print(); sep()
        label = c("Détections", BOLD, RED) if positives else c("Détections suspectes", BOLD, YELLOW)
        print(f"  {label}\n")
        for eng, r in positives[:limit]:
            print(f"    {c('✗', RED)}  {c(eng, WHITE):<26}  {c(r.get('result','?'), RED)}")
        for eng, r in suspicious[:5]:
            print(f"    {c('?', YELLOW)}  {c(eng, WHITE):<26}  {c(r.get('result','?'), YELLOW)}")
        print()

def _render_file_items(items: list, count: int, title: str):
    if not items and count == 0:
        return
    sep()
    print(f"  {c(title, BOLD, WHITE)}  {c(f'({count} total, {len(items)} affichés)', DIM)}\n")
    for item in items:
        attr  = item.get("attributes", {})
        sha   = item.get("id", "?")[:16] + "…"
        names = (attr.get("names") or [])[:2]
        name  = ", ".join(names) if names else attr.get("meaningful_name", "?")
        ftype = attr.get("type_description", "")
        stats = attr.get("last_analysis_stats", {})
        mal   = stats.get("malicious", 0)
        total = sum(stats.values()) or 1
        col   = RED + BOLD if mal > 2 else (YELLOW if mal > 0 else DIM)
        print(f"    {c(sha, DIM)}  {c(f'{mal}/{total}', col):<20}  {c(name, WHITE)}  {c(f'[{ftype}]', DIM)}")
    print()

def _render_resolutions(items: list, count: int):
    if not items and count == 0:
        return
    sep()
    print(f"  {c('Résolutions DNS', BOLD, WHITE)}  {c(f'({count} total, {len(items)} affichés)', DIM)}\n")
    for item in items:
        attr = item.get("attributes", {})
        host = attr.get("hostname", item.get("id", "?"))
        date = (attr.get("date") or attr.get("last_resolved", ""))[:10]
        print(f"    {c('·', DIM)}  {c(host, CYAN):<40}  {c(date, DIM)}")
    print()

def _render_ssl(items: list, count: int):
    if not items and count == 0:
        return
    sep()
    print(f"  {c('Certificats SSL historiques', BOLD, WHITE)}  {c(f'({count} total, {len(items)} affichés)', DIM)}\n")
    for item in items:
        attr    = item.get("attributes", {})
        subj    = attr.get("subject", {})
        issuer  = attr.get("issuer", {})
        valid   = attr.get("validity", {})
        cn      = subj.get("CN") or subj.get("common_name", "?")
        iss_cn  = issuer.get("CN") or issuer.get("common_name", "?")
        not_bef = (valid.get("not_before", "") or "")[:10]
        not_aft = (valid.get("not_after",  "") or "")[:10]
        serial  = attr.get("serial_number", "")[:20]
        thumb   = (attr.get("thumbprint") or "")[:24]
        print(f"    {c('Subject:', DIM)}  {c(cn, WHITE)}")
        print(f"    {c('Issuer :', DIM)}  {c(iss_cn, DIM)}")
        if not_bef or not_aft:
            print(f"    {c('Validité:', DIM)} {c(not_bef, DIM)} → {c(not_aft, DIM)}")
        if serial:
            print(f"    {c('Serial :', DIM)}  {c(serial, DIM)}")
        if thumb:
            print(f"    {c('Thumb  :', DIM)}  {c(thumb, DIM)}")
        print()

def _render_url_items(items: list, count: int):
    if not items and count == 0:
        return
    sep()
    print(f"  {c('URLs associées', BOLD, WHITE)}  {c(f'({count} total, {len(items)} affichés)', DIM)}\n")
    for item in items:
        attr  = item.get("attributes", {})
        url   = attr.get("url", item.get("id", "?"))
        stats = attr.get("last_analysis_stats", {})
        mal   = stats.get("malicious", 0)
        total = sum(stats.values()) or 1
        col   = RED + BOLD if mal > 0 else DIM
        print(f"    {c(f'{mal}/{total}', col):<12}  {c(url[:80], WHITE)}")
    print()

def _render_crowdsourced_ids(attr: dict):
    """Affiche les alertes IDS crowdsourcées (Suricata/Snort) depuis VT.
    Champ API : crowdsourced_ids_results (liste) + crowdsourced_ids_stats (dict niveaux)."""
    results = attr.get("crowdsourced_ids_results") or []
    stats   = attr.get("crowdsourced_ids_stats") or {}
    if not results and not stats:
        return
    sep()
    total = sum(stats.values()) if stats else len(results)
    high  = stats.get("high", 0)
    med   = stats.get("medium", 0)
    col   = RED + BOLD if high > 0 else (YELLOW if med > 0 else WHITE)
    print(f"  {c('Crowdsourced IDS Rules', BOLD, WHITE)}  {c(f'({total} règle(s))', col)}\n")
    if stats:
        parts = []
        for level, color in [("high", RED), ("medium", YELLOW), ("low", DIM), ("info", DIM)]:
            n = stats.get(level, 0)
            if n:
                parts.append(c(f"{level}: {n}", color))
        if parts:
            print("    " + "  ".join(parts))
        print()
    for rule in results[:15]:
        sev     = rule.get("alert_severity", "?")
        msg     = rule.get("rule_msg", "?")
        src     = rule.get("rule_source", "")
        rule_id = rule.get("rule_id", "")
        cat     = rule.get("rule_category", "")
        col     = RED + BOLD if sev == "high" else (YELLOW if sev == "medium" else DIM)
        print(f"    {c(f'[{sev}]', col):<22}  {c(msg, WHITE)}")
        if src or rule_id:
            print(f"      {c(f'{src}  {rule_id}'.strip(), DIM)}")
        if cat:
            print(f"      {c(f'catégorie: {cat}', DIM)}")
    if len(results) > 15:
        print(c(f"    … {len(results) - 15} règles supplémentaires", DIM))
    print()

def _render_yara_rules(attr: dict):
    """Affiche les YARA rules crowdsourcées qui ont matché ce fichier/IP.
    Champ API : crowdsourced_yara_results (liste de règles avec ruleset_name, rule_name, etc.)."""
    rules = attr.get("crowdsourced_yara_results") or []
    if not rules:
        return
    sep()
    print(f"  {c('Crowdsourced YARA Rules', BOLD, WHITE)}  {c(f'({len(rules)} match(es))', MAGENTA)}\n")
    for rule in rules[:15]:
        ruleset = rule.get("ruleset_name", "?")
        name    = rule.get("rule_name", "?")
        author  = rule.get("author", "")
        desc    = rule.get("description", "")
        src     = rule.get("source", "")
        print(f"    {c('▸', MAGENTA)}  {c(name, WHITE)}  {c(f'[{ruleset}]', DIM)}")
        if author:
            print(f"      {c('auteur:', DIM)} {c(author, DIM)}")
        if desc:
            print(f"      {c('desc  :', DIM)} {c(desc[:100], DIM)}")
        if src:
            print(f"      {c('source:', DIM)} {c(src[:80], DIM)}")
    if len(rules) > 15:
        print(c(f"    … {len(rules) - 15} règles supplémentaires", DIM))
    print()

def _render_sigma_rules(attr: dict):
    """Affiche les Sigma rules crowdsourcées qui ont matché (analyse comportementale).
    Champ API : sigma_analysis_results + sigma_analysis_stats (critical/high/medium/low)."""
    rules = attr.get("sigma_analysis_results") or []
    stats = attr.get("sigma_analysis_stats") or {}
    if not rules and not stats:
        return
    sep()
    total = sum(stats.values()) if stats else len(rules)
    crit  = stats.get("critical", 0)
    high  = stats.get("high", 0)
    col   = RED + BOLD if crit > 0 or high > 0 else YELLOW
    print(f"  {c('Crowdsourced Sigma Rules', BOLD, WHITE)}  {c(f'({total} règle(s))', col)}\n")
    if stats:
        parts = []
        for level, color in [("critical", RED + BOLD), ("high", RED), ("medium", YELLOW), ("low", DIM)]:
            n = stats.get(level, 0)
            if n:
                parts.append(c(f"{level}: {n}", color))
        if parts:
            print("    " + "  ".join(parts))
        print()
    for rule in rules[:15]:
        sev     = rule.get("rule_level", "?")
        title   = rule.get("rule_title", "?")
        src     = rule.get("rule_source", "")
        rule_id = rule.get("rule_id", "")
        matches = rule.get("match_context") or []
        col     = RED + BOLD if sev in ("critical", "high") else (YELLOW if sev == "medium" else DIM)
        print(f"    {c(f'[{sev}]', col):<22}  {c(title, WHITE)}")
        if src or rule_id:
            print(f"      {c(f'{src}  {rule_id}'.strip(), DIM)}")
        if matches:
            snippet = str(matches[0])[:120]
            print(f"      {c('match:', DIM)} {c(snippet, DIM)}")
    if len(rules) > 15:
        print(c(f"    … {len(rules) - 15} règles supplémentaires", DIM))
    print()

def _render_sandbox_verdicts(attr: dict):
    """Affiche les verdicts des sandboxes d'analyse dynamique (ex: DrWeb, Triage, etc.).
    Champ API : sandbox_verdicts (dict keyed par nom de sandbox → category/malware_names)."""
    verdicts = attr.get("sandbox_verdicts") or {}
    if not verdicts:
        return
    sep()
    print(f"  {c('Dynamic Analysis — Sandbox Verdicts', BOLD, WHITE)}\n")
    for sandbox, v in verdicts.items():
        cat     = v.get("category", "?")
        names   = v.get("malware_names") or []
        classif = v.get("malware_classification") or []
        col     = RED + BOLD if cat == "malicious" else (YELLOW if cat == "suspicious" else GREEN)
        print(f"    {c(sandbox, WHITE):<38}  {c(cat, col)}")
        if names:
            print(f"      {c('Malware    :', DIM)} {c(', '.join(names[:5]), RED)}")
        if classif:
            print(f"      {c('Classif.   :', DIM)} {c(', '.join(classif[:5]), YELLOW)}")
    print()

def _render_contacted(items: list, count: int, title: str, is_ip: bool = False):
    if not items and count == 0:
        return
    sep()
    print(f"  {c(title, BOLD, WHITE)}  {c(f'({count} total)', DIM)}\n")
    for item in items:
        attr  = item.get("attributes", {})
        ident = item.get("id", "?")
        if is_ip:
            country = attr.get("country", "")
            asn     = attr.get("asn", "")
            mal     = attr.get("last_analysis_stats", {}).get("malicious", 0)
            col     = RED if mal > 0 else DIM
            print(f"    {c(ident, col):<20}  {c(country, DIM)}  AS{asn}")
        else:
            mal = attr.get("last_analysis_stats", {}).get("malicious", 0)
            col = RED if mal > 0 else DIM
            print(f"    {c(ident, col)}")
    print()

# ── render IP ──────────────────────────────────────────────────────────────────

def render_ip(ip: str, data: dict, as_json: bool = False):
    if as_json:
        print(json.dumps(data, indent=2)); return

    main = data.get("main", {})
    if main.get("_error"):
        print(c(f"  Erreur : {main['_error']}", RED)); return

    attr = main.get("data", {}).get("attributes", {})
    sep("═")
    print(f"  {c('VirusTotal — IP', BOLD, WHITE)}  {c('›', DIM)}  {c(ip, CYAN, BOLD)}")
    sep()
    print()

    stats = attr.get("last_analysis_stats", {})
    print(f"  {'Détections':<26} {_stats_line(stats)}")
    print(f"  {'Pays':<26} {c(attr.get('country','n/a'), WHITE)}")
    print(f"  {'ASN':<26} {c(str(attr.get('asn','n/a')), DIM)}")
    print(f"  {'AS owner':<26} {c(attr.get('as_owner','n/a'), DIM)}")
    print(f"  {'Réseau':<26} {c(attr.get('network','n/a'), DIM)}")
    print(f"  {'Réputation':<26} {c(attr.get('reputation', 0), BOLD)}")

    votes = attr.get("total_votes", {})
    if votes:
        print(f"  {'Votes communauté':<26} "
              f"{c('malveillant', RED)}:{votes.get('malicious',0)}  "
              f"{c('clean', GREEN)}:{votes.get('harmless',0)}")

    tags = attr.get("tags") or []
    if tags:
        print(f"  {'Tags':<26} " + "  ".join(c(f"[{t}]", CYAN) for t in tags))

    cats = attr.get("categories", {})
    if cats:
        print(); sep()
        print(f"  {c('Catégories', BOLD)}")
        for engine, cat in list(cats.items())[:8]:
            print(f"    {c(engine, DIM):<30} {c(cat, YELLOW)}")

    _render_detections(attr.get("last_analysis_results", {}))
    _render_yara_rules(attr)
    _render_sigma_rules(attr)
    _render_crowdsourced_ids(attr)

    # ── sections relationships (--full) ──
    _render_file_items(
        data.get("communicating_files", {}).get("items", []),
        data.get("communicating_files", {}).get("count", 0),
        "Communicating Files  (établissent des connexions vers cette IP)",
    )
    _render_file_items(
        data.get("referrer_files", {}).get("items", []),
        data.get("referrer_files", {}).get("count", 0),
        "Referrer Files  (contiennent cette IP comme URL/référence)",
    )
    _render_url_items(
        data.get("urls", {}).get("items", []),
        data.get("urls", {}).get("count", 0),
    )
    _render_resolutions(
        data.get("resolutions", {}).get("items", []),
        data.get("resolutions", {}).get("count", 0),
    )
    _render_ssl(
        data.get("historical_ssl_certificates", {}).get("items", []),
        data.get("historical_ssl_certificates", {}).get("count", 0),
    )

    sep("═")

# ── render URL ─────────────────────────────────────────────────────────────────

def render_url(url_target: str, data: dict, as_json: bool = False):
    if as_json:
        print(json.dumps(data, indent=2)); return

    main = data.get("main", {})
    if main.get("_error"):
        print(c(f"  Erreur : {main['_error']}", RED)); return

    attr = main.get("data", {}).get("attributes", {})
    sep("═")
    print(f"  {c('VirusTotal — URL', BOLD, WHITE)}  {c('›', DIM)}  {c(url_target, CYAN, BOLD)}")
    sep()
    print()

    stats = attr.get("last_analysis_stats", {})
    print(f"  {'Détections':<26} {_stats_line(stats)}")
    final = attr.get("last_final_url", "")
    if final and final != url_target:
        print(f"  {'Redirection finale':<26} {c(final[:80], DIM)}")
    print(f"  {'Titre page':<26} {c(attr.get('title','n/a'), WHITE)}")
    print(f"  {'Réputation':<26} {c(attr.get('reputation', 0), BOLD)}")

    tags = attr.get("tags") or []
    if tags:
        print(f"  {'Tags':<26} " + "  ".join(c(f"[{t}]", CYAN) for t in tags))

    cats = attr.get("categories", {})
    if cats:
        print(); sep()
        print(f"  {c('Catégories', BOLD)}")
        for engine, cat in list(cats.items())[:8]:
            print(f"    {c(engine, DIM):<30} {c(cat, YELLOW)}")

    _render_detections(attr.get("last_analysis_results", {}))
    _render_yara_rules(attr)
    _render_sigma_rules(attr)
    _render_crowdsourced_ids(attr)

    # ── sections relationships (--full) ──
    _render_contacted(
        data.get("contacted_ips", {}).get("items", []),
        data.get("contacted_ips", {}).get("count", 0),
        "Contacted IPs", is_ip=True,
    )
    _render_contacted(
        data.get("contacted_domains", {}).get("items", []),
        data.get("contacted_domains", {}).get("count", 0),
        "Contacted Domains",
    )
    _render_file_items(
        data.get("downloaded_files", {}).get("items", []),
        data.get("downloaded_files", {}).get("count", 0),
        "Downloaded Files",
    )
    _render_url_items(
        data.get("redirecting_urls", {}).get("items", []),
        data.get("redirecting_urls", {}).get("count", 0),
    )

    sep("═")

# ── render Hash ────────────────────────────────────────────────────────────────

def render_hash(h: str, data: dict, as_json: bool = False):
    if as_json:
        print(json.dumps(data, indent=2)); return

    main = data.get("main", {})
    attr = main.get("data", {}).get("attributes", {})
    sep("═")
    print(f"  {c('VirusTotal — Hash', BOLD, WHITE)}  {c('›', DIM)}  {c(h, CYAN, BOLD)}")
    sep()
    print()

    stats = attr.get("last_analysis_stats", {})
    print(f"  {'Détections':<26} {_stats_line(stats)}")
    names = (attr.get("names") or [])[:3]
    print(f"  {'Nom(s)':<26} {c(', '.join(names) or 'n/a', WHITE)}")
    print(f"  {'Type':<26} {c(attr.get('type_description','n/a'), DIM)}")
    print(f"  {'Taille':<26} {c(str(attr.get('size','?')) + ' bytes', DIM)}")

    # timestamps sont des unix timestamps
    for label, key in [("Première soumission", "first_submission_date"),
                        ("Dernière analyse",   "last_analysis_date")]:
        ts = attr.get(key)
        if ts:
            import datetime
            dt = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")
            print(f"  {label:<26} {c(dt, DIM)}")

    tags = attr.get("tags") or []
    if tags:
        print(f"  {'Tags':<26} " + "  ".join(c(f"[{t}]", CYAN) for t in tags))

    _render_detections(attr.get("last_analysis_results", {}))
    _render_yara_rules(attr)
    _render_sigma_rules(attr)
    _render_crowdsourced_ids(attr)
    _render_sandbox_verdicts(attr)
    sep("═")

def render(target: str, kind: str, data: dict, as_json: bool = False):
    if kind == "ip":    render_ip(target, data, as_json)
    elif kind == "url": render_url(target, data, as_json)
    else:               render_hash(target, data, as_json)

# ── run ────────────────────────────────────────────────────────────────────────

def run_lookup(targets, api_key, as_json=False, export=None, full=False):
    results = {}
    for i, target in enumerate(targets):
        if i > 0 and not full:
            time.sleep(16)
        try:
            kind, data = query_vt(target, api_key, full=full)
            results[target] = {"type": kind, "data": data}
            if not export:
                render(target, kind, data, as_json)
        except urllib.error.HTTPError as e:
            if e.code == 401:
                print(c(f"\n  Clé API invalide ou expirée (401).", RED, BOLD))
                print(f"  Vérifie ta clé sur {c('https://www.virustotal.com/gui/my-apikey', CYAN)}")
                sys.exit(1)
            if e.code == 429:
                print(c(f"\n  Quota dépassé (429) — limite gratuite : 500 req/jour, 4 req/min.", YELLOW, BOLD))
            else:
                print(c(f"  Erreur HTTP {e.code} pour {target} : {e.reason}", RED))
            results[target] = {"error": f"HTTP {e.code}: {e.reason}"}
        except ValueError as e:
            print(c(f"\n  {e}", RED))
            results[target] = {"error": str(e)}
        except Exception as e:
            print(c(f"  Erreur pour {target} : {e}", RED))
            results[target] = {"error": str(e)}

    if export:
        with open(export, "w") as fh:
            json.dump(results, fh, indent=2)
        print(c(f"\n  Exporté → {export}", GREEN))
    return results

# ── menu interactif ────────────────────────────────────────────────────────────

def menu_interactif(api_key):
    print()
    print(c("  ╔═══════════════════════════════════════╗", CYAN))
    print(c("  ║  ", CYAN) + c("VirusTotal Lookup", BOLD, WHITE) + c("  (API v3)         ║", CYAN))
    print(c("  ╚═══════════════════════════════════════╝", CYAN))
    print()
    print(f"  {c('1', BOLD)}  Rechercher une IP / URL / hash")
    print(f"  {c('2', BOLD)}  Rechercher une IP / URL / hash  {c('(mode complet : +files/SSL/DNS)', DIM)}")
    print(f"  {c('3', BOLD)}  Charger une liste depuis un fichier")
    print(f"  {c('q', BOLD)}  Quitter")
    print()

    while True:
        choix = input(c("  Choix › ", CYAN)).strip().lower()

        if choix == "q":
            print(c("  Au revoir.\n", DIM)); sys.exit(0)

        elif choix in ("1", "2"):
            full   = (choix == "2")
            target = input(c("  IP / URL / hash › ", CYAN)).strip()
            if not target: print(c("  Rien saisi.", DIM)); continue
            as_json = input(c("  Sortie JSON ? (o/N) › ", DIM)).strip().lower() == "o"
            if full:
                print(c("  Mode complet : jusqu'à 6 appels API (~1min sur plan gratuit).", DIM))
            print()
            run_lookup([target], api_key, as_json=as_json, full=full)
            print()
            if input(c("  Nouvelle recherche ? (O/n) › ", DIM)).strip().lower() == "n":
                sys.exit(0)
            menu_interactif(api_key); break

        elif choix == "3":
            path = input(c("  Chemin du fichier › ", CYAN)).strip()
            try:
                with open(path) as fh:
                    targets = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
            except FileNotFoundError:
                print(c(f"  Fichier introuvable : {path}", RED)); continue
            if not targets: print(c("  Fichier vide.", DIM)); continue
            as_json = input(c("  Sortie JSON ? (o/N) › ", DIM)).strip().lower() == "o"
            export  = input(c("  Fichier export JSON (vide = pas) › ", DIM)).strip() or None
            full    = input(c("  Mode complet (files/SSL/DNS) ? (o/N) › ", DIM)).strip().lower() == "o"
            print()
            run_lookup(targets, api_key, as_json=as_json, export=export, full=full)
            print()
            if input(c("  Nouvelle recherche ? (O/n) › ", DIM)).strip().lower() == "n":
                sys.exit(0)
            menu_interactif(api_key); break

        else:
            print(c("  Choix invalide.", DIM))

# ── main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(prog="virustotal_lookup", description="VirusTotal lookup (API v3)")
    parser.add_argument("targets", nargs="*")
    parser.add_argument("--file",  "-f")
    parser.add_argument("--json",  action="store_true")
    parser.add_argument("--export","-e")
    parser.add_argument("--key",   "-k")
    parser.add_argument("--full",  "-F", action="store_true",
                        help="Ajoute communicating files, referrer files, SSL, DNS, URLs (+5 appels API)")
    args = parser.parse_args()

    api_key = get_api_key(args.key)
    targets = list(args.targets)
    if args.file:
        try:
            with open(args.file) as fh:
                targets += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
        except FileNotFoundError:
            print(c(f"Fichier introuvable : {args.file}", RED), file=sys.stderr); sys.exit(1)

    if not targets:
        menu_interactif(api_key)
        return

    if args.full:
        print(c(f"  Mode --full : jusqu'à 6 appels API par cible (~1min sur plan gratuit).", DIM))
    run_lookup(targets, api_key, as_json=args.json, export=args.export, full=args.full)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {c('Ctrl+C détecté — Au revoir.', YELLOW)}\n")
        sys.exit(0)

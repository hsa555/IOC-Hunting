#!/usr/bin/env python3
# Made by hsa5
"""
Setup — configuration des clés API pour ThreatHunting
Lance ce script une seule fois après avoir récupéré les scripts.

Les clés sont chiffrées (Fernet/AES) et stockées dans
~/.config/threat_hunting/keys.json (chmod 600).

Requiert : pip install -r requirements.txt
"""

import sys
import re
import json
import getpass
import urllib.request
import urllib.parse
import urllib.error

import sys as _sys, os as _os
_path = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), ".internal")
if _path not in _sys.path:
    _sys.path.insert(0, _path)
from config_loader import (
    CONFIG_FILE, SERVICES,
    load_key, save_key_to_config, all_keys,
    is_encrypted, verify_passphrase, set_passphrase, get_passphrase,
    _load_all, _save_all, _encrypt,
    load_setting, save_setting,
)

RESET  = "\033[0m";  BOLD  = "\033[1m";  DIM  = "\033[2m"
RED    = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
CYAN   = "\033[96m"; WHITE = "\033[97m"

def c(text, *codes): return "".join(codes) + str(text) + RESET
def sep(ch="─", w=70): print(c(ch * w, DIM))

DESCRIPTIONS = {
    "urlhaus":    "Lookup de malwares / URLs malveillantes (abuse.ch)",
    "abuseipdb":  "Score d'abus sur les IPs, rapports communautaires",
    "virustotal": "Scan multi-antivirus d'IPs, URLs et fichiers/hashes",
    "shodan":     "Donnees d'indexation reseau (ports, services, vulnerabilites)",
    "censys":     "Ports ouverts et services (250 req/mois gratuit)",
}

# ── tests de clés ─────────────────────────────────────────────────────────────

def test_urlhaus(key):
    url  = "https://urlhaus-api.abuse.ch/v1/url/"
    data = urllib.parse.urlencode({"url": "http://example.com"}).encode()
    req  = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("Auth-Key", key)
    with urllib.request.urlopen(req, timeout=8) as resp:
        r = json.loads(resp.read().decode())
        return "query_status" in r

def test_abuseipdb(key):
    params = urllib.parse.urlencode({"ipAddress": "8.8.8.8", "maxAgeInDays": "1"})
    req = urllib.request.Request(f"https://api.abuseipdb.com/api/v2/check?{params}")
    req.add_header("Key", key)
    req.add_header("Accept", "application/json")
    with urllib.request.urlopen(req, timeout=8) as resp:
        return "data" in json.loads(resp.read().decode())

def test_virustotal(key):
    req = urllib.request.Request("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8")
    req.add_header("x-apikey", key)
    with urllib.request.urlopen(req, timeout=8) as resp:
        return "data" in json.loads(resp.read().decode())

def test_shodan(key):
    url = f"https://api.shodan.io/api-info?key={urllib.parse.quote(key)}"
    with urllib.request.urlopen(url, timeout=8) as resp:
        r = json.loads(resp.read().decode())
        return "query_credits" in r or "plan" in r

_CENSYS_UA = "censys-python/2.2.12 (+https://github.com/censys/censys-python)"

def test_censys(key):
    req = urllib.request.Request(
        "https://api.platform.censys.io/v3/global/asset/host/8.8.8.8"
    )
    req.add_header("Authorization", f"Bearer {key}")
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", _CENSYS_UA)
    with urllib.request.urlopen(req, timeout=8) as resp:
        r = json.loads(resp.read().decode())
        return "result" in r

TESTERS = {
    "urlhaus":    test_urlhaus,
    "abuseipdb":  test_abuseipdb,
    "virustotal": test_virustotal,
    "shodan":     test_shodan,
    "censys":     test_censys,
}

def try_test(service, key):
    try:
        return TESTERS[service](key), None
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}"
    except Exception as e:
        return False, str(e)

# ── setup passphrase ──────────────────────────────────────────────────────────

def _prompt_new_passphrase() -> str:
    """Demande une nouvelle passphrase avec confirmation."""
    print()
    while True:
        try:
            pp = getpass.getpass(c("  Nouvelle passphrase › ", CYAN))
            if not pp:
                print(c("  Passphrase vide non autorisee.", RED)); continue
            if len(pp) < 8:
                print(c("  Minimum 8 caracteres.", RED)); continue
            confirm = getpass.getpass(c("  Confirme la passphrase › ", CYAN))
        except (EOFError, KeyboardInterrupt):
            print(); print(c("  Annule.", DIM)); sys.exit(0)
        if pp == confirm:
            return pp
        print(c("  Les passphrases ne correspondent pas, reessaie.", RED))

def setup_passphrase():
    """
    Configure ou vérifie la passphrase maître.
    - Config chiffrée : déverrouille d'abord, puis propose de changer
    - Config plaintext ou absente : crée une nouvelle passphrase
    Met le résultat en cache via set_passphrase() pour le reste du setup.
    """
    print()
    sep("═")
    print(f"  {c('Chiffrement des cles API', BOLD, WHITE)}")
    print(f"  {c('Algorithme : Fernet (AES-128-CBC + HMAC-SHA256)', DIM)}")
    print(f"  {c('KDF        : PBKDF2-HMAC-SHA256 — 480 000 iterations', DIM)}")
    print(f"  {c('Passphrase : 3 options — voir README.md pour le detail', DIM)}")
    sep("═")

    if is_encrypted():
        print(f"\n  {c('Config chiffree detectee.', GREEN)}")
        print(f"  Entre ta passphrase pour deverrouiller les cles actuelles.\n")

        # déverrouillage
        for attempt in range(3):
            pp = get_passphrase(c("  Passphrase actuelle › ", CYAN))
            if pp is None:
                print(); sys.exit(0)
            if verify_passphrase(pp):
                set_passphrase(pp)
                print(c("  Deverrouille.", GREEN, BOLD))
                break
            print(c("  Passphrase incorrecte.", RED))
            if attempt == 2:
                print(c("  Trop de tentatives.", RED)); sys.exit(1)
        else:
            sys.exit(1)

        print()
        change = input(c("  Changer la passphrase ? (o/N) › ", DIM)).strip().lower()
        if change == "o":
            new_pp = _prompt_new_passphrase()
            # rechiffrer avec la nouvelle passphrase
            existing_keys = _load_all()
            set_passphrase(new_pp)
            _save_all(existing_keys)
            print(c("  Passphrase mise a jour et config rechiffree.", GREEN, BOLD))

    else:
        if CONFIG_FILE.exists():
            print(f"\n  {c('Config en clair detectee — migration vers le chiffrement.', YELLOW)}")
        else:
            print(f"\n  {c('Premiere configuration — creation de la passphrase.', DIM)}")
        print(f"  Cette passphrase chiffrera tes cles API. Ne l'oublie pas.\n")
        pp = _prompt_new_passphrase()
        set_passphrase(pp)
        print(c("  Passphrase definie.", GREEN, BOLD))

# ── setup par service ─────────────────────────────────────────────────────────

def setup_service(service):
    meta     = SERVICES[service]
    desc     = DESCRIPTIONS[service]
    existing = load_key(service)

    print()
    sep()
    print(f"  {c(meta['label'], BOLD, WHITE)}")
    print(f"  {c(desc, DIM)}")
    print(f"  {c('Cle API gratuite :', DIM)} {c(meta['url'], CYAN)}")

    if existing:
        masked = existing[:6] + "..." + existing[-4:] if len(existing) > 12 else "***"
        print(f"  {c('Cle actuelle:', DIM)} {c(masked, DIM)}")
        if input(c("  Garder cette cle ? (O/n) › ", DIM)).strip().lower() != "n":
            return existing

    key = input(c("  Colle ta cle API (vide = ignorer) › ", CYAN)).strip()
    if not key:
        print(c("  Ignore.", DIM))
        return existing or ""

    print(c("  Test de la cle...", DIM), end=" ", flush=True)
    ok, err = try_test(service, key)
    if ok:
        print(c("OK", GREEN, BOLD))
        save_key_to_config(service, key)
    else:
        print(c(f"Echec ({err or 'inconnu'})", YELLOW))
        print(c("  La cle sera sauvegardee quand meme.", DIM))
        if input(c("  Sauvegarder quand meme ? (O/n) › ", DIM)).strip().lower() != "n":
            save_key_to_config(service, key)
        else:
            return existing or ""
    return key

# ── setup Censys (clé composite api_id:api_secret) ───────────────────────────

def setup_censys():
    meta     = SERVICES["censys"]
    existing = load_key("censys")

    print()
    sep()
    print(f"  {c(meta['label'], BOLD, WHITE)}")
    print(f"  {c(DESCRIPTIONS['censys'], DIM)}")
    print(f"  {c('Personal Access Token :', DIM)} {c(meta['url'], CYAN)}")
    print(f"  {c('Format               :', DIM)} {c('censys_XXXXXXXX_XXXXXXXXXXXXXXXXXX', DIM)}")

    if existing:
        masked = existing[:14] + "..." if len(existing) > 14 else "***"
        print(f"  {c('Token actuel:', DIM)} {c(masked, DIM)}")
        if input(c("  Garder ce token ? (O/n) › ", DIM)).strip().lower() != "n":
            return existing

    try:
        key = getpass.getpass(c("  Personal Access Token › ", CYAN)).strip()
    except (EOFError, KeyboardInterrupt):
        print(); return existing or ""
    if not key:
        print(c("  Ignore.", DIM))
        return existing or ""

    print(c("  Test du token...", DIM), end=" ", flush=True)
    ok, err = try_test("censys", key)
    if ok:
        print(c("OK", GREEN, BOLD))
        save_key_to_config("censys", key)
    else:
        print(c(f"Echec ({err or 'inconnu'})", YELLOW))
        if input(c("  Sauvegarder quand meme ? (O/n) › ", DIM)).strip().lower() != "n":
            save_key_to_config("censys", key)
        else:
            return existing or ""
    return key

def _setup_any(svc):
    if svc == "censys":
        setup_censys()
    else:
        setup_service(svc)

# ── cache ─────────────────────────────────────────────────────────────────────

def _parse_duration(s: str) -> int | None:
    """Convertit une durée humaine en secondes.
    Unités supportées :
      h          → heures        ex: 24h, 12h
      j / d      → jours         ex: 2j, 7d
      sem / w    → semaines      ex: 1sem, 2w
      min / m    → minutes       ex: 30min
    Sans unité   → heures        ex: 48 → 48h
    """
    s = s.strip().lower()
    if not s:
        return None
    # sem/wk/min avant h/j/d/w/m pour éviter un match partiel
    m = re.match(r'^(\d+(?:[.,]\d+)?)\s*(sem|min|h|j|d|w|m)?$', s)
    if not m:
        return None
    val  = float(m.group(1).replace(',', '.'))
    unit = m.group(2) or 'h'  # sans unité = heures
    mult = {
        'h': 3600,
        'j': 86400, 'd': 86400,
        'sem': 604800, 'w': 604800,
        'min': 60, 'm': 60,
    }
    return int(val * mult[unit])

def _fmt_duration(seconds: int) -> str:
    """Affiche une durée lisible depuis un nombre de secondes."""
    if seconds % 604800 == 0:
        n = seconds // 604800
        return f"{n} semaine{'s' if n > 1 else ''} ({n * 7}j)"
    if seconds % 86400 == 0:
        n = seconds // 86400
        return f"{n} jour{'s' if n > 1 else ''} ({n * 24}h)"
    if seconds % 3600 == 0:
        return f"{seconds // 3600}h"
    if seconds % 60 == 0:
        return f"{seconds // 60}min"
    return f"{seconds}s"

def setup_cache():
    """Configure la durée de rétention du cache des résultats."""
    current = int(load_setting("cache_ttl") or 86400)
    print()
    sep()
    print(f"  {c('Cache des résultats', BOLD, WHITE)}")
    print(f"  {c('Durée actuelle :', DIM)} {c(_fmt_duration(current), WHITE)}")
    print(f"  {c('Unités : h (heures)  j (jours)  sem (semaines)  ex: 48h  2j  1sem', DIM)}")
    print()
    raw = input(c("  Durée du cache  (24h par défaut) › ", CYAN)).strip()
    if not raw:
        ttl = 86400
    else:
        ttl = _parse_duration(raw)
        if ttl is None or ttl < 60:
            print(c("  Format non reconnu ou trop court (min : 1min). Valeur maintenue à 24h.", YELLOW))
            ttl = 86400
    save_setting("cache_ttl", ttl)
    print(c(f"  Cache configuré : {_fmt_duration(ttl)}", GREEN, BOLD))

# ── résumé ─────────────────────────────────────────────────────────────────────

def print_banner():
    print()
    print(c("  ╔══════════════════════════════════════════════╗", CYAN))
    print(c("  ║  ", CYAN) + c("ThreatHunting — Setup des cles API", BOLD, WHITE) + c("       ║", CYAN))
    print(c("  ╚══════════════════════════════════════════════╝", CYAN))
    print()
    for svc, meta in SERVICES.items():
        print(f"    {c('·', DIM)}  {c(meta['label'], WHITE)}")
    print()
    print(f"  Stockage : {c(str(CONFIG_FILE), DIM)}")
    enc_status = c("chiffre (Fernet/AES)", GREEN) if is_encrypted() else c("non chiffre", YELLOW)
    print(f"  Statut   : {enc_status}")
    print()

def print_summary():
    keys = all_keys()
    print()
    sep("═")
    print(f"  {c('Resume de la configuration', BOLD, WHITE)}\n")
    all_ok = True
    for svc, meta in SERVICES.items():
        key = keys.get(svc, "")
        if key:
            masked = key[:6] + "..." + key[-4:] if len(key) > 12 else "***"
            status = c("OK  configuree", GREEN)
            val    = c(masked, DIM)
        else:
            status = c("--  manquante", YELLOW)
            val    = c("non configuree", DIM)
            all_ok = False
        print(f"  {status}  {c(meta['label'], WHITE):<22}  {val}")

    print()
    enc = is_encrypted()
    enc_label = c("oui (Fernet/AES)", GREEN, BOLD) if enc else c("non — relance setup.py", YELLOW)
    print(f"  {c('Chiffrement', BOLD):<28}  {enc_label}")
    print()

    if all_ok:
        print(c("  Toutes les cles sont configurees.", GREEN, BOLD))
    else:
        print(c("  Certaines cles manquent.", YELLOW))
    print()
    print(f"  Reconfigurer   : {c('python setup.py', CYAN)}")
    print(f"  Analyser       : {c('python main.py <ip-ou-url>', CYAN)}")
    print(f"  Passphrase     : {c('option 1', BOLD)} prompt interactif  {c('(recommande)', GREEN)}")
    print(f"                   {c('option 2', BOLD)} {c('THREAT_HUNTING_PASSPHRASE=<pp> python3 main.py', DIM)}  {c('(inline, risque limite)', YELLOW)}")
    print(f"                   {c('option 3', BOLD)} {c('export THREAT_HUNTING_PASSPHRASE=<pp>', DIM)}  {c('(shell persistent, plus risque)', RED)}")
    sep("═")
    print()

# ── menu modification ─────────────────────────────────────────────────────────

def _unlock():
    """Déverrouille la passphrase en mémoire sans proposer de changement."""
    if not is_encrypted():
        return
    for attempt in range(3):
        pp = get_passphrase(c("  Passphrase › ", CYAN))
        if pp is None:
            print(); sys.exit(0)
        if verify_passphrase(pp):
            set_passphrase(pp)
            print(c("  Déverrouillé.", GREEN))
            return
        print(c("  Passphrase incorrecte.", RED))
        if attempt == 2:
            print(c("  Trop de tentatives.", RED)); sys.exit(1)

def _change_passphrase():
    """Propose de changer la passphrase (passphrase actuelle déjà en cache mémoire)."""
    new_pp = _prompt_new_passphrase()
    existing = _load_all()
    set_passphrase(new_pp)
    _save_all(existing)
    print(c("  Passphrase mise à jour.", GREEN, BOLD))

def _run_keys_menu():
    """Sous-menu : choisir quelle(s) clé(s) API modifier."""
    svcs = list(SERVICES.keys())
    print()
    print(f"  {c('1', BOLD)}  Toutes les clés")
    for i, svc in enumerate(svcs, 2):
        print(f"  {c(str(i), BOLD)}  {SERVICES[svc]['label']}")
    print()
    choix = input(c("  Choix › ", CYAN)).strip()
    if choix == "1":
        for svc in svcs:
            _setup_any(svc)
    else:
        try:
            svc = svcs[int(choix) - 2]
            _setup_any(svc)
        except (ValueError, IndexError):
            print(c("  Choix invalide.", DIM))

def setup_web_port():
    """Configure le port par défaut de l'interface web."""
    current = int(load_setting("web_port") or 5000)
    print()
    sep()
    print(f"  {c('Port interface web', BOLD, WHITE)}")
    print(f"  {c(f'Port actuel : {current}', DIM)}")
    print()
    raw = input(c(f"  Port  (Entrée = garder {current}) › ", CYAN)).strip()
    if not raw:
        return
    if raw.isdigit() and 1024 <= int(raw) <= 65535:
        save_setting("web_port", int(raw))
        print(c(f"  Port configuré : {raw}", GREEN, BOLD))
    else:
        print(c("  Port invalide — inchangé (doit être entre 1024 et 65535).", YELLOW))

def _run_change_menu():
    """Menu affiché quand une config existe déjà."""
    while True:
        print()
        sep()
        print(f"  {c('Que veux-tu modifier ?', BOLD, WHITE)}\n")
        print(f"  {c('1', BOLD)}  Passphrase")
        print(f"  {c('2', BOLD)}  Clés API")
        print(f"  {c('3', BOLD)}  Durée du cache")
        print(f"  {c('4', BOLD)}  Port interface web")
        print(f"  {c('5', BOLD)}  Tout reconfigurer")
        print(f"  {c('q', BOLD)}  Quitter")
        print()
        try:
            choix = input(c("  Choix › ", CYAN)).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print(); break

        if choix == "q":
            break
        elif choix == "1":
            _change_passphrase()
        elif choix == "2":
            _run_keys_menu()
        elif choix == "3":
            setup_cache()
        elif choix == "4":
            setup_web_port()
        elif choix == "5":
            setup_passphrase()
            setup_cache()
            setup_web_port()
            for svc in SERVICES:
                _setup_any(svc)
            break
        else:
            print(c("  Choix invalide.", DIM))

# ── main ──────────────────────────────────────────────────────────────────────

def main():
    print_banner()

    if CONFIG_FILE.exists():
        # Config existante → déverrouille puis affiche le menu de modification
        _unlock()
        _run_change_menu()
    else:
        # Première configuration → flow séquentiel complet
        setup_passphrase()
        setup_cache()
        for svc in SERVICES:
            _setup_any(svc)

    print_summary()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {c('Ctrl+C — Au revoir.', YELLOW)}\n")
        sys.exit(0)

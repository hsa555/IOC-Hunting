#!/usr/bin/env python3
# Made by hsa5
"""
AbuseIPDB Lookup CLI
====================
Usage interactif : python abuseipdb_lookup.py
Usage direct     : python abuseipdb_lookup.py <ip> [<ip2> ...]
                   python abuseipdb_lookup.py --file ips.txt --json --export out.json

Clé API gratuite (1000 req/jour) : https://www.abuseipdb.com/account/api
Configurée via setup.py ou variable d'env : export ABUSEIPDB_API_KEY="ta_clé"

Retourne : abuseConfidenceScore (0-100), rapports communautaires avec catégories
d'attaque (port scan, SSH brute-force, DDoS, SQL injection, etc.) et commentaires.
"""

import sys
import os
import json
import argparse
import urllib.request
import urllib.parse
from pathlib import Path

import sys as _sys, os as _os
_path = _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), ".internal")
if _path not in _sys.path:
    _sys.path.insert(0, _path)
from config_loader import load_key, save_key_to_config

RESET  = "\033[0m";  BOLD  = "\033[1m";  DIM  = "\033[2m"
RED    = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
CYAN   = "\033[96m"; WHITE = "\033[97m"; MAGENTA = "\033[95m"

def c(text, *codes): return "".join(codes) + str(text) + RESET
def sep(ch="─", w=70): print(c(ch * w, DIM))

def badge(text, style):
    styles = {"danger": RED+BOLD, "warn": YELLOW, "ok": GREEN, "info": CYAN, "dim": DIM}
    return c(f" {text} ", styles.get(style, DIM))

CATEGORIES = {
    1:  "DNS Compromise", 2:  "DNS Poisoning",  3:  "Fraud Orders",
    4:  "DDoS Attack",    5:  "FTP Brute-Force", 6:  "Ping of Death",
    7:  "Phishing",       8:  "Fraud VoIP",      9:  "Open Proxy",
    10: "Web Spam",       11: "Email Spam",      12: "Blog Spam",
    13: "VPN IP",         14: "Port Scan",       15: "Hacking",
    16: "SQL Injection",  17: "Spoofing",        18: "Brute-Force",
    19: "Bad Web Bot",    20: "Exploited Host",  21: "Web App Attack",
    22: "SSH",            23: "IoT Targeted",
}

def get_api_key(provided=None):
    if provided:
        return provided
    key = load_key("abuseipdb")
    if key:
        return key
    print()
    print(c("  Clé API AbuseIPDB requise.", YELLOW, BOLD))
    print(f"  Obtiens-en une gratuitement sur {c('https://www.abuseipdb.com/account/api', CYAN)}")
    print(f"  Ou lance {c('python setup.py', CYAN)} pour configurer toutes les clés.")
    print()
    key = input(c("  Colle ta clé API › ", CYAN)).strip()
    if not key:
        print(c("  Aucune clé fournie, abandon.", RED)); sys.exit(1)
    if input(c("  Sauvegarder ? (O/n) › ", DIM)).strip().lower() != "n":
        save_key_to_config("abuseipdb", key)
    return key

def query_abuseipdb(ip, api_key, max_age=90, verbose=True):
    params = urllib.parse.urlencode({
        "ipAddress":    ip,
        "maxAgeInDays": max_age,
        "verbose":      "" if verbose else None,
    })
    url = f"https://api.abuseipdb.com/api/v2/check?{params}"
    req = urllib.request.Request(url)
    req.add_header("Key", api_key)
    req.add_header("Accept", "application/json")
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode())

def score_color(score):
    if score >= 75: return RED + BOLD
    if score >= 25: return YELLOW
    return GREEN

def render(ip, data, as_json=False):
    if as_json:
        print(json.dumps(data, indent=2)); return

    d = data.get("data", {})
    sep("═")
    print(f"  {c('AbuseIPDB lookup', BOLD, WHITE)}  {c('›', DIM)}  {c(ip, CYAN, BOLD)}")
    sep()

    score = d.get("abuseConfidenceScore", 0)
    total = d.get("totalReports", 0)
    print()
    print(f"  {'Score de confiance abus':<28} {c(f'{score}%', score_color(score))}")
    print(f"  {'Rapports totaux':<28} {c(total, BOLD)}")
    print(f"  {'Rapports derniers 90j':<28} {c(d.get('numDistinctUsers', 0), BOLD)}")
    print(f"  {'Dernière activité':<28} {c(d.get('lastReportedAt') or 'n/a', DIM)}")
    print()
    print(f"  {'Pays':<28} {c(d.get('countryCode') or 'n/a', WHITE)}")
    print(f"  {'ISP':<28} {c(d.get('isp') or 'n/a', WHITE)}")
    print(f"  {'Domaine':<28} {c(d.get('domain') or 'n/a', DIM)}")
    print(f"  {'Usage type':<28} {c(d.get('usageType') or 'n/a', DIM)}")
    print(f"  {'IP publique':<28} {c('oui' if d.get('isPublic') else 'non', DIM)}")
    print(f"  {'Whitelist':<28} {c('oui' if d.get('isWhitelisted') else 'non', DIM)}")
    print(f"  {'Tor':<28} {c('oui' if d.get('isTor') else 'non', RED if d.get('isTor') else DIM)}")

    reports = d.get("reports") or []
    if reports:
        cat_ids = {}
        for r in reports:
            for cid in (r.get("categories") or []):
                cat_ids[cid] = cat_ids.get(cid, 0) + 1
        if cat_ids:
            print(); sep()
            print(f"  {c('Categories attaques', BOLD)}")
            for cid, cnt in sorted(cat_ids.items(), key=lambda x: -x[1]):
                name = CATEGORIES.get(cid, f"Cat#{cid}")
                print(f"    {c('⚠', YELLOW)}  {c(name, YELLOW, BOLD):<30} {c(f'×{cnt}', DIM)}")

        print(); sep()
        print(f"  {c('Derniers rapports', BOLD)}  (jusqu'à 10)\n")
        for r in reports[:10]:
            cat_names = ", ".join(CATEGORIES.get(cid, f"#{cid}") for cid in (r.get("categories") or []))
            print(f"    {c(r.get('reportedAt','?'), DIM)}  {c(r.get('reporterCountryCode','??'), WHITE)}  {c(cat_names or 'n/a', YELLOW)}")
            if r.get("comment"):
                comment = r["comment"][:120].replace("\n", " ")
                print(f"      {c(comment, DIM)}")
        print()

    sep("═")

def run_lookup(targets, api_key, as_json=False, export=None):
    results = {}
    for ip in targets:
        try:
            data = query_abuseipdb(ip, api_key)
            results[ip] = data
            if not export:
                render(ip, data, as_json=as_json)
        except urllib.error.HTTPError as e:
            body = e.read().decode() if hasattr(e, "read") else ""
            if e.code == 401:
                print(c(f"\n  Clé API invalide (401).", RED, BOLD)); sys.exit(1)
            if e.code == 429:
                print(c(f"\n  Quota dépassé (429) — limite gratuite : 1000 req/jour.", YELLOW, BOLD))
            else:
                print(c(f"  Erreur HTTP {e.code} pour {ip} : {body[:200]}", RED))
            results[ip] = {"error": f"HTTP {e.code}"}
        except Exception as e:
            print(c(f"  Erreur pour {ip} : {e}", RED))
            results[ip] = {"error": str(e)}
    if export:
        with open(export, "w") as fh:
            json.dump(results, fh, indent=2)
        print(c(f"\n  Exporté → {export}", GREEN))
    return results

def menu_interactif(api_key):
    print()
    print(c("  ╔══════════════════════════════════╗", CYAN))
    print(c("  ║  ", CYAN) + c("AbuseIPDB Lookup", BOLD, WHITE) + c("              ║", CYAN))
    print(c("  ╚══════════════════════════════════╝", CYAN))
    print()
    print(f"  {c('1', BOLD)}  Rechercher une IP")
    print(f"  {c('2', BOLD)}  Rechercher une liste d'IPs (saisie manuelle)")
    print(f"  {c('3', BOLD)}  Charger une liste depuis un fichier")
    print(f"  {c('q', BOLD)}  Quitter")
    print()

    while True:
        choix = input(c("  Choix › ", CYAN)).strip().lower()

        if choix == "q":
            print(c("  Au revoir.\n", DIM)); sys.exit(0)

        elif choix == "1":
            ip = input(c("  IP › ", CYAN)).strip()
            if not ip: print(c("  Rien saisi.", DIM)); continue
            as_json = input(c("  Sortie JSON ? (o/N) › ", DIM)).strip().lower() == "o"
            print()
            run_lookup([ip], api_key, as_json=as_json)
            print()
            if input(c("  Nouvelle recherche ? (O/n) › ", DIM)).strip().lower() == "n":
                sys.exit(0)
            menu_interactif(api_key); break

        elif choix == "2":
            print(c("  Entre les IPs une par ligne. Ligne vide pour terminer.", DIM))
            targets = []
            while True:
                line = input(c("  › ", DIM)).strip()
                if not line: break
                targets.append(line)
            if not targets: print(c("  Aucune IP saisie.", DIM)); continue
            as_json = input(c("  Sortie JSON ? (o/N) › ", DIM)).strip().lower() == "o"
            export  = input(c("  Fichier export JSON (vide = pas d'export) › ", DIM)).strip() or None
            print()
            run_lookup(targets, api_key, as_json=as_json, export=export)
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
            print(c(f"  {len(targets)} IP(s) chargée(s).", GREEN))
            as_json = input(c("  Sortie JSON ? (o/N) › ", DIM)).strip().lower() == "o"
            export  = input(c("  Fichier export JSON (vide = pas d'export) › ", DIM)).strip() or None
            print()
            run_lookup(targets, api_key, as_json=as_json, export=export)
            print()
            if input(c("  Nouvelle recherche ? (O/n) › ", DIM)).strip().lower() == "n":
                sys.exit(0)
            menu_interactif(api_key); break

        else:
            print(c("  Choix invalide.", DIM))

def main():
    parser = argparse.ArgumentParser(prog="abuseipdb_lookup", description="AbuseIPDB IP lookup")
    parser.add_argument("ips", nargs="*")
    parser.add_argument("--file", "-f")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--export", "-e")
    parser.add_argument("--key", "-k")
    args = parser.parse_args()

    api_key = get_api_key(args.key)
    targets = list(args.ips)
    if args.file:
        try:
            with open(args.file) as fh:
                targets += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
        except FileNotFoundError:
            print(c(f"Fichier introuvable : {args.file}", RED), file=sys.stderr); sys.exit(1)

    if not targets:
        menu_interactif(api_key)
        return

    run_lookup(targets, api_key, as_json=args.json, export=args.export)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {c('Ctrl+C détecté — Au revoir.', YELLOW)}\n")
        sys.exit(0)

#!/usr/bin/env python3
# Made by hsa5
"""
Censys Host Lookup CLI
======================
Usage interactif : python censys_lookup.py
Usage direct     : python censys_lookup.py <ip> [<ip2> ...]
                   python censys_lookup.py --file ips.txt --json --export out.json

Clé API gratuite (250 req/mois) : https://search.censys.io/account/api
Configurée via setup.py ou variable d'env : export CENSYS_API_KEY="api_id:api_secret"

Utilise l'API Censys v3 Platform (/v3/global/asset/host/{ip}).
Retourne ports ouverts, services détaillés (protocol, software, labels), ASN, géoloc.
La clé est un Personal Access Token (PAT) au format censys_XXXXXXXX_XXXXXXXXXX.
"""

import sys
import os
import json
import getpass
import argparse
import urllib.request
import urllib.parse
import urllib.error

import sys as _sys, os as _os
_path = _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), ".internal")
if _path not in _sys.path:
    _sys.path.insert(0, _path)
from config_loader import load_key, save_key_to_config

RESET  = "\033[0m";  BOLD  = "\033[1m";  DIM  = "\033[2m"
RED    = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
CYAN   = "\033[96m"; WHITE = "\033[97m"

def c(text, *codes): return "".join(codes) + str(text) + RESET
def sep(ch="─", w=70): print(c(ch * w, DIM))

def get_api_key(provided=None):
    if provided:
        return provided
    key = load_key("censys")
    if key:
        return key
    print()
    print(c("  Personal Access Token Censys requis.", YELLOW, BOLD))
    print(f"  Crée un token sur : {c('https://app.censys.io/user/tokens', CYAN)}")
    print(f"  Format : {c('censys_XXXXXXXX_XXXXXXXXXXXXXXXXXXXXXXXXXX', DIM)}")
    print(f"  Ou lance {c('python setup.py', CYAN)} pour configurer toutes les clés.")
    print()
    key = getpass.getpass(c("  Personal Access Token › ", CYAN)).strip()
    if not key:
        print(c("  Aucun token fourni, abandon.", RED)); sys.exit(1)
    if input(c("  Sauvegarder ? (O/n) › ", DIM)).strip().lower() != "n":
        save_key_to_config("censys", key)
    return key

_CENSYS_UA = "censys-python/2.2.12 (+https://github.com/censys/censys-python)"

def _censys_get(path, api_key):
    url = f"https://api.platform.censys.io/v3/global{path}"
    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Bearer {api_key}")
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", _CENSYS_UA)
    with urllib.request.urlopen(req, timeout=15) as resp:
        body = resp.read()
        if not body or not body.strip():
            raise ValueError(f"Censys : réponse vide ({path})")
        return json.loads(body.decode("utf-8", errors="replace"))

def query_censys(ip, api_key):
    return _censys_get(f"/asset/host/{urllib.parse.quote(ip, safe='')}", api_key)

def render(ip, data, as_json=False):
    if as_json:
        print(json.dumps(data, indent=2)); return

    resource = data.get("result", {}).get("resource", {})
    services = resource.get("services") or []
    asn_info = resource.get("autonomous_system") or {}
    loc_info = resource.get("location") or {}
    last_upd = (resource.get("scan_time") or "")[:10]

    sep("═")
    print(f"  {c('Censys lookup', BOLD, WHITE)}  {c('›', DIM)}  {c(ip, CYAN, BOLD)}")
    sep()
    print()

    if asn_info:
        asn_n = asn_info.get("asn", "?")
        asn_d = asn_info.get("description", "")
        print(f"  {'ASN':<26} {c(f'AS{asn_n}  —  {asn_d}', DIM)}")
        if asn_info.get("name"):
            print(f"  {'Organisation':<26} {c(asn_info['name'], WHITE)}")
        if asn_info.get("bgp_prefix"):
            print(f"  {'Préfixe BGP':<26} {c(asn_info['bgp_prefix'], DIM)}")
    country = (loc_info.get("country") or loc_info.get("country_code") or "")
    if country:
        print(f"  {'Pays':<26} {c(country, WHITE)}")
    if last_upd:
        print(f"  {'Dernière MAJ':<26} {c(last_upd, DIM)}")

    ports = sorted({s["port"] for s in services if s.get("port")})
    if ports:
        print(); sep()
        print(f"  {c('Ports ouverts', BOLD)}  ({len(ports)} détectés)")
        print(f"  {c(', '.join(str(p) for p in ports), YELLOW, BOLD)}")

    if services:
        print(); sep()
        print(f"  {c('Services', BOLD)}  ({len(services)} entrée(s))\n")
        for svc in services:
            port    = svc.get("port", "?")
            proto   = (svc.get("transport_protocol") or "tcp").upper()
            name    = svc.get("protocol") or svc.get("service_name") or "?"
            sw_list = svc.get("software") or []
            raw_lbl = svc.get("labels") or []
            labels  = [l.get("value", "") if isinstance(l, dict) else str(l)
                       for l in raw_lbl]

            sw_s = ""
            if sw_list:
                sw    = sw_list[0]
                parts = [sw.get("vendor",""), sw.get("product","")]
                sw_s  = "  " + c(" ".join(p for p in parts if p), DIM)

            print(f"  {c(f'{port}/{proto}', YELLOW, BOLD):<28}  {c(name, WHITE)}{sw_s}")
            if labels:
                print(f"    {c('Labels:', DIM)}   {c(', '.join(l for l in labels if l), CYAN)}")
            print()

    sep("═")

def run_lookup(targets, api_key, as_json=False, export=None):
    results = {}
    for ip in targets:
        try:
            data = query_censys(ip, api_key)
            results[ip] = data
            if not export:
                render(ip, data, as_json=as_json)
        except urllib.error.HTTPError as e:
            body = ""
            try: body = e.read().decode("utf-8", errors="replace")
            except Exception: pass
            if e.code in (401, 403):
                print(c(f"\n  Clé API invalide (HTTP {e.code}).", RED, BOLD))
                print(c("  Vérifie ton API ID + Secret : https://search.censys.io/account/api", DIM))
                sys.exit(1)
            elif e.code == 404:
                print(c(f"  {ip} — aucune donnée Censys pour cette IP.", DIM))
                results[ip] = {"_not_found": True}
            elif e.code == 429:
                print(c(f"  {ip} — quota atteint (250 req/mois sur plan gratuit).", YELLOW))
                results[ip] = {"error": "rate limit"}
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
    print(c("  ╔═══════════════════════════════════╗", CYAN))
    print(c("  ║  ", CYAN) + c("Censys Host Lookup", BOLD, WHITE) + c("          ║", CYAN))
    print(c("  ╚═══════════════════════════════════╝", CYAN))
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
            print(c("  Choix invalide (1, 2, 3 ou q).", DIM))

def main():
    parser = argparse.ArgumentParser(prog="censys_lookup", description="Censys IP lookup")
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
            print(c(f"Fichier introuvable : {args.file}", RED), file=sys.stderr)
            sys.exit(1)

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

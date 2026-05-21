#!/usr/bin/env python3
# Made by hsa5
"""
Shodan Lookup CLI (gratuit — endpoint /shodan/host/{ip})
=========================================================
Usage interactif : python shodan_lookup.py
Usage direct     : python shodan_lookup.py <ip> [<ip2> ...]
                   python shodan_lookup.py --file ips.txt --json --export out.json

Clé API gratuite : https://account.shodan.io/
Configurée via setup.py ou variable d'env : export SHODAN_API_KEY="ta_clé"

Note : le plan gratuit Shodan ne permet pas de scan à la demande ni de filtres
avancés, mais donne accès aux données indexées pour chaque IP via /shodan/host/{ip}.

Sans clé (ou erreur 401/403), main.py se rabat automatiquement sur Shodan InternetDB
(endpoint public, gratuit, ports/vulns/hostnames sans clé).
"""

import sys
import os
import json
import argparse
import urllib.request
import urllib.parse
import urllib.error
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

def get_api_key(provided=None):
    if provided:
        return provided
    key = load_key("shodan")
    if key:
        return key
    print()
    print(c("  Clé API Shodan requise.", YELLOW, BOLD))
    print(f"  Obtiens-en une gratuitement sur {c('https://account.shodan.io/', CYAN)}")
    print(f"  Ou lance {c('python setup.py', CYAN)} pour configurer toutes les clés.")
    print()
    key = input(c("  Colle ta clé API › ", CYAN)).strip()
    if not key:
        print(c("  Aucune clé fournie, abandon.", RED)); sys.exit(1)
    if input(c("  Sauvegarder ? (O/n) › ", DIM)).strip().lower() != "n":
        save_key_to_config("shodan", key)
    return key

def _shodan_get(path: str, api_key: str) -> dict:
    url = f"https://api.shodan.io{path}?key={urllib.parse.quote(api_key, safe='')}"
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=15) as resp:
        body = resp.read()
        if not body or not body.strip():
            raise ValueError(f"Réponse vide de Shodan ({path})")
        return json.loads(body.decode("utf-8", errors="replace"))

def check_api_key(api_key: str) -> dict:
    """Appelle /api-info pour diagnostiquer la clé et le plan."""
    try:
        return _shodan_get("/api-info", api_key)
    except urllib.error.HTTPError as e:
        return {"_error": e.code}
    except Exception as e:
        return {"_error": str(e)}

def query_shodan(ip, api_key):
    return _shodan_get(f"/shodan/host/{urllib.parse.quote(ip, safe='')}", api_key)

def render(ip, data, as_json=False):
    if as_json:
        print(json.dumps(data, indent=2)); return

    sep("═")
    print(f"  {c('Shodan lookup', BOLD, WHITE)}  {c('›', DIM)}  {c(ip, CYAN, BOLD)}")
    sep()
    print()

    print(f"  {'Organisation':<26} {c(data.get('org','n/a'), WHITE)}")
    print(f"  {'ISP':<26} {c(data.get('isp','n/a'), DIM)}")
    print(f"  {'ASN':<26} {c(data.get('asn','n/a'), DIM)}")
    print(f"  {'Pays':<26} {c(data.get('country_name','n/a'), WHITE)}")
    city = data.get("city") or data.get("region_code") or ""
    if city: print(f"  {'Ville':<26} {c(city, DIM)}")
    print(f"  {'OS':<26} {c(data.get('os','n/a'), DIM)}")
    print(f"  {'Dernière MAJ':<26} {c(data.get('last_update','n/a'), DIM)}")

    hostnames = data.get("hostnames") or []
    if hostnames:
        print(f"  {'Hostnames':<26} {c(', '.join(hostnames[:5]), DIM)}")

    domains = data.get("domains") or []
    if domains:
        print(f"  {'Domaines':<26} {c(', '.join(domains[:5]), DIM)}")

    tags = data.get("tags") or []
    if tags:
        print(f"  {'Tags':<26} " + "  ".join(c(f"[{t}]", CYAN) for t in tags))

    ports = data.get("ports") or []
    if ports:
        print(); sep()
        print(f"  {c('Ports ouverts', BOLD)}  ({len(ports)} détectés)")
        print(f"  {c(', '.join(str(p) for p in sorted(ports)), YELLOW, BOLD)}")

    vulns = data.get("vulns") or []
    if vulns:
        print(); sep()
        print(f"  {c('Vulnérabilités détectées', BOLD, RED)}  ({len(vulns)})\n")
        for v in sorted(vulns):
            print(f"    {c('⚠', RED)}  {c(v, RED, BOLD)}")
        print()

    services = data.get("data") or []
    if services:
        print(); sep()
        print(f"  {c('Services / Banners', BOLD)}  ({len(services)} entrée(s))\n")
        for svc in services[:10]:
            port      = svc.get("port", "?")
            transport = svc.get("transport", "tcp")
            product   = svc.get("product", "")
            version   = svc.get("version", "")
            banner    = (svc.get("data") or "").strip()[:120].replace("\n", " ↵ ")
            cpe       = svc.get("cpe") or []
            module    = svc.get("_shodan", {}).get("module", "")
            timestamp = svc.get("timestamp", "")

            pv = f"{product} {version}".strip() or "?"
            print(f"  {c(f'{port}/{transport}', YELLOW, BOLD):<28}  {c(pv, WHITE)}")
            if module:    print(f"    {c('Module:', DIM)}   {c(module, DIM)}")
            if cpe:       print(f"    {c('CPE:', DIM)}      {c(', '.join(cpe[:2]), DIM)}")
            if timestamp: print(f"    {c('Vu le:', DIM)}    {c(timestamp[:10], DIM)}")
            if banner:    print(f"    {c('Banner:', DIM)}   {c(banner, DIM)}")
            print()

    sep("═")

def run_lookup(targets, api_key, as_json=False, export=None):
    results = {}
    for ip in targets:
        try:
            data = query_shodan(ip, api_key)
            results[ip] = data
            if not export:
                render(ip, data, as_json=as_json)
        except urllib.error.HTTPError as e:
            body = ""
            try: body = e.read().decode("utf-8", errors="replace")
            except Exception: pass
            if e.code == 401:
                print(c(f"\n  Clé API invalide (401).", RED, BOLD)); sys.exit(1)
            elif e.code == 403:
                print()
                print(c(f"  Shodan 403 Forbidden pour {ip}", RED, BOLD))
                print(c("  Causes possibles :", YELLOW))
                print(c("    1. Clé de type 'Demo' — génère une vraie clé API dans", DIM))
                print(c("       https://account.shodan.io/  (onglet 'API Key')", CYAN))
                print(c("    2. Plan sans accès à l'endpoint /shodan/host/{ip}", DIM))
                print(c("    3. Crédits de requête épuisés (100/mois sur plan gratuit)", DIM))
                print()
                info = check_api_key(api_key)
                if "_error" not in info:
                    plan    = info.get("plan", "n/a")
                    credits = info.get("query_credits", "n/a")
                    scan_cr = info.get("scan_credits", "n/a")
                    print(f"  {c('Plan actuel :', DIM)}   {c(plan, YELLOW, BOLD)}")
                    print(f"  {c('Query credits :', DIM)} {c(str(credits), BOLD)}")
                    print(f"  {c('Scan credits :', DIM)}  {c(str(scan_cr), BOLD)}")
                    if str(credits) == "0":
                        print(c("\n  Crédits épuisés — attends le renouvellement mensuel.", RED))
                    elif plan in ("dev", "demo", ""):
                        print(c("\n  Plan 'dev/demo' : accès limité. Upgrade sur shodan.io.", YELLOW))
                else:
                    print(c(f"  /api-info a aussi échoué : {info['_error']}", DIM))
                results[ip] = {"error": "HTTP 403"}
            elif e.code == 404:
                print(c(f"  {ip} — aucune donnée Shodan disponible pour cette IP.", DIM))
                results[ip] = {"error": "not found"}
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
    print(c("  ║  ", CYAN) + c("Shodan Lookup", BOLD, WHITE) + c("                 ║", CYAN))
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
    parser = argparse.ArgumentParser(prog="shodan_lookup", description="Shodan IP lookup (gratuit)")
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

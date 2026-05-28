#!/usr/bin/env python3
# Made by hsa5
"""
URLhaus URL Lookup CLI
======================
Usage interactif : python urlhaus_lookup.py
Usage direct     : python urlhaus_lookup.py <url> [<url2> ...]
                   python urlhaus_lookup.py --file urls.txt --json --export out.json

Clé API gratuite : https://auth.abuse.ch/
Configurée via setup.py ou variable d'env : export URLHAUS_API_KEY="ta_clé"

Vérifie si une URL est répertoriée dans URLhaus (base de malware URLs abuse.ch).
Retourne : statut (online/offline), menace, blacklists (SURBL, URIBL), payloads
avec SHA256/MD5 et résultat VirusTotal associé.

Note : si la clé est invalide, l'API renvoie du HTML au lieu de JSON — détecté
et converti en ValueError avec message explicatif.
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
CYAN   = "\033[96m"; WHITE = "\033[97m"

def c(text, *codes): return "".join(codes) + str(text) + RESET
def sep(ch="─", w=70): print(c(ch * w, DIM))

def badge(text, style):
    styles = {"danger": RED+BOLD, "warn": YELLOW, "ok": GREEN, "info": CYAN, "dim": DIM}
    return c(f" {text} ", styles.get(style, DIM))

def get_api_key(provided=None):
    if provided:
        return provided
    key = load_key("urlhaus")
    if key:
        return key
    print()
    print(c("  Clé API URLhaus requise.", YELLOW, BOLD))
    print(f"  Obtiens-en une gratuitement sur {c('https://auth.abuse.ch/', CYAN)}")
    print(f"  Ou lance {c('python setup.py', CYAN)} pour configurer toutes les clés.")
    print()
    key = input(c("  Colle ta clé API › ", CYAN)).strip()
    if not key:
        print(c("  Aucune clé fournie, abandon.", RED)); sys.exit(1)
    if input(c("  Sauvegarder ? (O/n) › ", DIM)).strip().lower() != "n":
        save_key_to_config("urlhaus", key)
    return key

def query_urlhaus(url_target, api_key):
    endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
    data = urllib.parse.urlencode({"url": url_target}).encode()
    req  = urllib.request.Request(endpoint, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("Auth-Key", api_key)
    with urllib.request.urlopen(req, timeout=10) as resp:
        raw = resp.read()
    if not raw or not raw.strip():
        raise ValueError(
            "Réponse vide de URLhaus — clé API probablement invalide.\n"
            "  Vérifie ta clé sur https://auth.abuse.ch/\n"
            "  Ou relance python setup.py pour la reconfigurer."
        )
    content_type = ""
    try:
        # certaines réponses d'erreur abuse.ch sont du HTML
        text = raw.decode("utf-8", errors="replace")
        if text.lstrip().startswith("<"):
            raise ValueError(
                f"URLhaus a répondu avec du HTML au lieu de JSON.\n"
                "  Cause probable : clé API invalide ou rate-limit.\n"
                f"  Début de la réponse : {text[:120]!r}"
            )
        return json.loads(text)
    except json.JSONDecodeError as e:
        preview = raw[:120].decode("utf-8", errors="replace")
        raise ValueError(f"Réponse non-JSON de URLhaus : {preview!r}") from e

def render(url_target, data, as_json=False):
    if as_json:
        print(json.dumps(data, indent=2)); return

    sep("═")
    status = data.get("query_status", "")
    print(f"  {c('URLhaus URL lookup', BOLD, WHITE)}  {c('›', DIM)}  {c(url_target, CYAN, BOLD)}")
    print(f"  {c('Status:', DIM)} {c(status, YELLOW)}")
    sep()

    if status == "no_results":
        print(f"\n  {c('✓', GREEN, BOLD)}  URL non référencée dans URLhaus.\n")
        sep("═"); return

    url_status = data.get("url_status", "")
    threat     = data.get("threat", "")
    tags       = data.get("tags") or []
    payloads   = data.get("payloads") or []
    date_added = data.get("date_added", "")
    host       = data.get("host", "")
    reporter   = data.get("reporter", "")

    is_on = url_status == "online"
    print()
    print(f"  {'Statut URL':<22} {badge('ONLINE', 'danger') if is_on else badge('offline', 'dim')}")
    if host:
        print(f"  {'Host':<22} {c(host, WHITE)}")
    if threat:
        print(f"  {'Menace':<22} {c(threat, RED, BOLD)}")
    if date_added:
        print(f"  {'Ajouté le':<22} {c(date_added, DIM)}")
    if reporter:
        print(f"  {'Signalé par':<22} {c(reporter, DIM)}")
    if data.get("id"):
        print(f"  {'Lien URLhaus':<22} {c('https://urlhaus.abuse.ch/url/' + str(data['id']) + '/', DIM)}")

    if tags:
        print(f"\n  {c('Tags:', DIM)} " + "  ".join(c(f"[{t}]", CYAN) for t in tags))

    bl = data.get("blacklists", {})
    if bl:
        print(); sep()
        print(f"  {c('Blacklists', BOLD)}")
        for k, v in bl.items():
            listed = v and v.lower() not in ("not listed", "")
            sym = c("✗", RED, BOLD) if listed else c("✓", GREEN)
            val = c(v, RED) if listed else c(v or "n/a", DIM)
            print(f"    {sym}  {k:<32} {val}")

    if payloads:
        print(); sep()
        print(f"  {c('Payloads / malwares', BOLD)}  ({len(payloads)} entrée(s))\n")
        for i, p in enumerate(payloads, 1):
            sig  = p.get("signature") or "?"
            ftyp = p.get("file_type") or "?"
            vt   = p.get("virustotal_percent")
            vt_s = c(f"VT:{vt}%", RED, BOLD) if vt and float(vt) > 0 else c("VT:n/a", DIM)
            print(f"  {c(f'{i:>3}.', DIM)} {c(sig, RED, BOLD)}  {c(f'[{ftyp}]', YELLOW)}  {vt_s}")
            if p.get("url"):       print(f"        {c('URL:   ', DIM)} {c(p['url'], CYAN)}")
            if p.get("sha256"):    print(f"        {c('SHA256:', DIM)} {c(p['sha256'], DIM)}")
            if p.get("md5"):       print(f"        {c('MD5:   ', DIM)} {c(p['md5'], DIM)}")
            if p.get("filename"):  print(f"        {c('File:  ', DIM)} {p['filename']}")
            if p.get("firstseen"): print(f"        {c('Vu le: ', DIM)} {p['firstseen']}")
            print()

    sep("═")

def run_lookup(targets, api_key, as_json=False, export=None):
    results = {}
    for target in targets:
        try:
            data = query_urlhaus(target, api_key)
            results[target] = data
            if not export:
                render(target, data, as_json=as_json)
        except urllib.error.HTTPError as e:
            if e.code == 401:
                print(c(f"\n  Clé API invalide ou expirée (401).", RED, BOLD))
                sys.exit(1)
            print(c(f"  Erreur HTTP {e.code} pour {target} : {e}", RED))
        except Exception as e:
            print(c(f"  Erreur pour {target} : {e}", RED))
            results[target] = {"error": str(e)}
    if export:
        with open(export, "w") as fh:
            json.dump(results, fh, indent=2)
        print(c(f"\n  Exporté → {export}", GREEN))
    return results

def menu_interactif(api_key):
    print()
    print(c("  ╔═══════════════════════════════════╗", CYAN))
    print(c("  ║  ", CYAN) + c("URLhaus URL Lookup", BOLD, WHITE) + c("  —  abuse.ch  ║", CYAN))
    print(c("  ╚═══════════════════════════════════╝", CYAN))
    print()
    print(f"  {c('1', BOLD)}  Rechercher une URL")
    print(f"  {c('2', BOLD)}  Rechercher une liste d'URLs (saisie manuelle)")
    print(f"  {c('3', BOLD)}  Charger une liste depuis un fichier")
    print(f"  {c('q', BOLD)}  Quitter")
    print()

    while True:
        choix = input(c("  Choix › ", CYAN)).strip().lower()

        if choix == "q":
            print(c("  Au revoir.\n", DIM)); sys.exit(0)

        elif choix == "1":
            url = input(c("  URL › ", CYAN)).strip()
            if not url: print(c("  Rien saisi.", DIM)); continue
            as_json = input(c("  Sortie JSON ? (o/N) › ", DIM)).strip().lower() == "o"
            print()
            run_lookup([url], api_key, as_json=as_json)
            print()
            if input(c("  Nouvelle recherche ? (O/n) › ", DIM)).strip().lower() == "n":
                sys.exit(0)
            menu_interactif(api_key); break

        elif choix == "2":
            print(c("  Entre les URLs une par ligne. Ligne vide pour terminer.", DIM))
            targets = []
            while True:
                line = input(c("  › ", DIM)).strip()
                if not line: break
                targets.append(line)
            if not targets: print(c("  Aucune URL saisie.", DIM)); continue
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
            print(c(f"  {len(targets)} URL(s) chargée(s).", GREEN))
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
    parser = argparse.ArgumentParser(prog="urlhaus_lookup", description="URLhaus URL lookup — abuse.ch")
    parser.add_argument("urls", nargs="*")
    parser.add_argument("--file", "-f")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--export", "-e")
    parser.add_argument("--key", "-k")
    args = parser.parse_args()

    api_key = get_api_key(args.key)

    targets = list(args.urls)
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

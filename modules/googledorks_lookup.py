#!/usr/bin/env python3
# Made by hsa5
"""
Google Dorks Lookup via SerpAPI
=================================
Usage : python modules/googledorks_lookup.py <ip>
        python modules/googledorks_lookup.py <ip> --json --num 10

Clé API gratuite (100 req/mois) : https://serpapi.com/
Configurable via setup.py ou variable d'env : export SERPAPI_KEY="ta_clé"
"""

import sys
import os
import json
import argparse
import urllib.request
import urllib.parse
import urllib.error
from concurrent.futures import ThreadPoolExecutor

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

EXCLUDED = [
    # Lookups / géoloc IP génériques
    "ipinfo.io", "ipaddress.com", "whatismyipaddress.com", "ip-lookup.net",
    "iplocation.net", "ipgeolocation.io", "maxmind.com", "ip2location.com",
    "db-ip.com", "ipapi.co", "ipwhois.io", "ipdata.co", "myip.ms",
    "infosniper.net", "robtex.com", "bgp.he.net", "hackertarget.com",
    "viewdns.info", "dnsdumpster.com", "securitytrails.com", "reverseiplookup.com",
    "ntunhs.net", "site-overview.com", "keycdn.com", "ipaddress.my",
    "ip-api.com", "ipstack.com", "freegeoip.app", "ipregistry.co",
    "geoiplookup.net", "iplocation.com", "locateip.com", "geobytes.com",
    "ipchicken.com", "2ip.ru", "ifconfig.me", "netify.ai",
    "ipgeolocation.net", "ipfly.com", "ipfingerprints.com", "ipdetective.io",
    # Threat intel / réputation / scoring
    "abuseipdb.com", "shodan.io", "virustotal.com", "censys.io",
    "pulsedive.com", "greynoise.io", "threatminer.org", "talosintelligence.com",
    "otx.alienvault.com", "urlscan.io", "hybrid-analysis.com", "any.run",
    "joesandbox.com", "isc.sans.edu", "threatintelligenceplatform.com",
    "cybergordon.com", "ipvoid.com", "ipqualityscore.com", "fraudguard.io",
    "scamalytics.com", "cleantalk.org", "stopforumspam.com", "ellio.tech",
    "spur.us", "criminalip.io", "binaryedge.io", "fullhunt.io",
    "fofa.info", "onyphe.io", "zoomeye.org", "leakix.net", "riskiq.com",
    "domainbigdata.com", "whoisxmlapi.com", "threatbook.io",
    "rdpguard.com", "dronebl.org",
    # Blacklists / blocklists / spam
    "spamhaus.org", "blocklist.de", "dshield.org", "emergingthreats.net",
    "abuse.ch", "feodotracker.abuse.ch", "bazaar.abuse.ch", "urlhaus.abuse.ch",
    "threatfox.abuse.ch", "sslbl.abuse.ch", "scumware.org",
    "barracudacentral.org", "sorbs.net", "anti-abuse.org", "dnsbl.info",
    "multirbl.valli.org", "projecthoneypot.org",
    # Outils réseau / whois / DNS
    "mxtoolbox.com", "urlvoid.com", "whois.domaintools.com", "domaintools.com",
    "netcraft.com", "proofpoint.com", "fortiguard.com", "dnschecker.org",
    # Honeypots / listes auto-générées / agrégateurs
    "honeymire.com", "perc.ddns.net", "binarydefense.com",
    # Listes de ranges / bases IP réseau
    "iplocationtools.com", "ipshu.com", "proxydocker.com", "networksdb.io",
    "ipaddressguide.com", "ipinfo.pro", "ipthreat.net", "sicehice.com",
    "ipnetninja.com", "ipspy.net", "ipsubnet.net", "bmcx.com",
    # Threat intel manqués
    "opentip.kaspersky.com", "kaspersky.com", "f-secure.com",
    "mcafee.com", "symantec.com", "sophos.com", "checkpoint.com",
    "crowdstrike.com", "recordedfuture.com", "mandiant.com",
    "threatconnect.com", "anomali.com", "misp-project.org",
    # Blacklists / spam supplémentaires
    "bl.isx.fr", "spamkill.co", "cinsscore.com",
    # BGP / routing
    "bgp.tools", "bgpview.io", "radb.net", "arin.net", "ripe.net",
    "apnic.net", "lacnic.net", "afrinic.net",
    # Analyse d'URLs
    "urlquery.net", "m.urlquery.net",
]

# Sous-ensemble envoyé dans la requête Google (limite ~32 opérateurs)
_EXCLUDED_QUERY = [
    "abuseipdb.com", "shodan.io", "virustotal.com", "censys.io",
    "ipinfo.io", "ipaddress.com", "whatismyipaddress.com", "pulsedive.com",
    "greynoise.io", "ipvoid.com", "spamhaus.org", "abuse.ch",
    "talosintelligence.com", "otx.alienvault.com", "urlscan.io",
    "mxtoolbox.com", "robtex.com", "bgp.he.net", "hackertarget.com",
    "db-ip.com", "maxmind.com", "ipqualityscore.com",
]

def _build_query(target: str, subnet: str = "") -> str:
    exclusions = " ".join(f"-site:{s}" for s in _EXCLUDED_QUERY)
    base = subnet if subnet else target
    return f'"{base}" {exclusions}'

def _get_key(provided=None):
    key = provided or load_key("serpapi") or ""
    if not key:
        print()
        print(c("  Clé API SerpAPI requise.", YELLOW, BOLD))
        print(f"  Gratuit : 100 req/mois → {c('https://serpapi.com/', CYAN)}")
        print(f"  Ou lance {c('python setup.py', CYAN)} pour configurer toutes les clés.")
        print()
        key = input(c("  Clé SerpAPI › ", CYAN)).strip()
        if not key:
            print(c("  Abandon.", RED)); sys.exit(1)
        if input(c("  Sauvegarder ? (O/n) › ", DIM)).strip().lower() != "n":
            save_key_to_config("serpapi", key)
    return key

def _subnet24(ip: str) -> str:
    parts = ip.split(".")
    # Point final pour forcer le contexte d'adresse IP dans Google
    # ex: "103.39.209." au lieu de "103.39.209" — évite les faux positifs CSV/scientifiques
    return ".".join(parts[:3]) + "." if len(parts) == 4 else ""

def _serpapi_search(q: str, api_key: str, num: int = 10, start: int = 0) -> dict:
    params = urllib.parse.urlencode({
        "api_key": api_key,
        "engine":  "google",
        "q":       q,
        "num":     min(num, 10),
        "start":   start,
        "safe":    "off",
    })
    req = urllib.request.Request(f"https://serpapi.com/search?{params}")
    req.add_header("Accept", "application/json")
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))

def query(target: str, api_key: str, num: int = 10) -> dict:
    """
    5 requêtes SerpAPI, lancées en parallèle (ThreadPoolExecutor) :
      1. page 1 (start=0)  — IP exacte avec exclusions
      2. page 2 (start=10) — IP exacte avec exclusions
      3. IP exacte SANS exclusions — capte ce que Google montre nativement
      4. IP + filetype:txt page 1  — raw IP lists, blocklists, CTI feeds texte
      5. IP + filetype:txt page 2  — (ex: sanyal.org/mirai-ips.txt)
    La déduplication respecte l'ordre ci-dessus (1→5), identique à la version
    séquentielle : seul l'ordre des appels réseau change, pas le résultat.
    """
    bq      = _build_query(target)
    clean_q = f'"{target}"'
    txt_q   = f'"{target}" filetype:txt'
    # (requête, start, marqueur _filetype_txt) — l'ordre = priorité de déduplication
    specs = [
        (bq,      0,  False),
        (bq,      10, False),
        (clean_q, 0,  False),
        (txt_q,   0,  True),
        (txt_q,   10, True),
    ]

    # Lancement parallèle ; pool.map préserve l'ordre des specs dans les réponses.
    with ThreadPoolExecutor(max_workers=len(specs)) as pool:
        responses = list(pool.map(
            lambda s: _serpapi_search(s[0], api_key, num=num, start=s[1]),
            specs,
        ))

    items = []
    seen  = set()
    for (_q, _start, is_txt), resp in zip(specs, responses):
        for item in (resp.get("organic_results") or []):
            link = item.get("link")
            if link not in seen:
                seen.add(link)
                items.append({**item, "_filetype_txt": True} if is_txt else item)

    # total : réponse de _build_query page 2 (start=10) — même source qu'avant
    total = responses[1].get("search_information", {}).get("total_results", "")
    return {"organic_results": items, "total": total}

def _domain(url: str) -> str:
    try:
        return urllib.parse.urlparse(url).netloc.lower().lstrip("www.")
    except Exception:
        return ""

def _filter(items: list, target: str) -> list:
    out = []
    for item in items:
        link    = item.get("link", "")
        snippet = item.get("snippet", "")
        title   = item.get("title", "")
        domain  = _domain(link)
        if any(domain == ex or domain.endswith("." + ex) for ex in EXCLUDED):
            continue
        # Pour les résultats filetype:txt : pas de vérification de présence —
        # le fichier contient l'IP mais Google peut ne pas la montrer dans le snippet
        if item.get("_filetype_txt"):
            out.append(item)
            continue
        # Sinon : l'IP doit apparaître dans le contenu visible ou le lien
        if target not in snippet and target not in title and target not in link:
            continue
        out.append(item)
    return out

def render(target: str, items: list, total: str = "", as_json: bool = False):
    if as_json:
        print(json.dumps(items, indent=2)); return

    sep("═")
    print(f"  {c('Google Dorks', BOLD, WHITE)}  {c('›', DIM)}  {c(target, CYAN, BOLD)}")
    if total:
        print(f"  {c(f'~{total} résultat(s) Google  |  {len(items)} après filtre', DIM)}")
    sep()

    if not items:
        print(f"\n  {c('Aucun résultat pertinent trouvé.', DIM)}\n")
        sep("═"); return

    print()
    for i, item in enumerate(items, 1):
        title   = item.get("title", "?")
        link    = item.get("link", "")
        snippet = (item.get("snippet") or "").replace("\n", " ").strip()

        print(f"  {c(f'{i:>2}.', DIM)}  {c(title, WHITE, BOLD)}")
        print(f"        {c(link, CYAN)}")
        if snippet:
            highlighted = snippet.replace(target, c(target, YELLOW, BOLD))
            print(f"        {c(highlighted[:160], DIM)}")
        print()

    sep("═")

def run(target: str, api_key: str, num: int = 10, as_json: bool = False):
    try:
        data  = query(target, api_key, num=num)
        items = _filter(data.get("organic_results") or [], target)
        total = str(data.get("total", ""))
        render(target, items, total=total, as_json=as_json)
        return items
    except urllib.error.HTTPError as e:
        body = ""
        try: body = e.read().decode("utf-8", errors="replace")
        except Exception: pass
        if e.code == 401:
            print(c("\n  Clé API invalide (401).", RED, BOLD))
        elif e.code == 429:
            print(c("\n  Quota mensuel atteint (100 req/mois sur plan gratuit).", YELLOW, BOLD))
        else:
            print(c(f"\n  Erreur HTTP {e.code} : {body[:200]}", RED))
        return []
    except Exception as e:
        print(c(f"\n  Erreur : {e}", RED))
        return []

def main():
    parser = argparse.ArgumentParser(prog="googledorks_lookup",
                                     description="Google Dorks — IP / domaine via SerpAPI")
    parser.add_argument("target", nargs="?")
    parser.add_argument("--json",  action="store_true")
    parser.add_argument("--num",   type=int, default=10)
    parser.add_argument("--key",   "-k")
    args = parser.parse_args()

    api_key = _get_key(args.key)

    target = args.target
    if not target:
        target = input(c("  IP / domaine › ", CYAN)).strip()
        if not target:
            print(c("  Rien saisi.", RED)); sys.exit(1)

    run(target, api_key, num=args.num, as_json=args.json)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {c('Ctrl+C — Au revoir.', YELLOW)}\n")
        sys.exit(0)

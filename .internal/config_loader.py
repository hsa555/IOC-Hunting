"""
Shared config loader — lit/écrit ~/.config/threat_hunting/keys.json
Chiffrement : Fernet (AES-128-CBC + HMAC-SHA256) via PBKDF2-HMAC-SHA256 (480 000 iter.)
Passphrase  : variable d'env THREAT_HUNTING_PASSPHRASE, cache mémoire, ou prompt interactif
"""

import json
import os
import sys
import base64
import getpass
from pathlib import Path

CONFIG_DIR     = Path.home() / ".config" / "threat_hunting"
CONFIG_FILE    = CONFIG_DIR / "keys.json"
SETTINGS_FILE  = CONFIG_DIR / "settings.json"  # paramètres non-sensibles (pas chiffrés)

SERVICES = {
    "urlhaus":    {"label": "URLhaus (abuse.ch)",  "url": "https://auth.abuse.ch/"},
    "abuseipdb":  {"label": "AbuseIPDB",           "url": "https://www.abuseipdb.com/account/api"},
    "virustotal": {"label": "VirusTotal",           "url": "https://www.virustotal.com/gui/my-apikey"},
    "shodan":     {"label": "Shodan",               "url": "https://account.shodan.io/"},
    "censys":     {"label": "Censys",               "url": "https://search.censys.io/account/api"},
}

_ENV_VAR      = "THREAT_HUNTING_PASSPHRASE"
_passphrase_cache: str | None = None
_env_consumed: bool = False  # env var est consommée une seule fois, puis ignorée si fausse
_data_cache: dict | None = None

# ── import crypto (erreur claire si manquant) ──────────────────────────────────

def _crypto():
    try:
        from cryptography.fernet import Fernet, InvalidToken
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        return Fernet, InvalidToken, PBKDF2HMAC, hashes
    except ImportError:
        print(
            "\n  [!] Module 'cryptography' manquant.\n"
            "      Lance : pip install -r requirements.txt\n",
            file=sys.stderr,
        )
        sys.exit(1)

# ── dérivation de clé ─────────────────────────────────────────────────────────

def _derive_fernet_key(passphrase: str, salt: bytes) -> bytes:
    _, _, PBKDF2HMAC, hashes = _crypto()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))

# ── chiffrement / déchiffrement ───────────────────────────────────────────────

def _encrypt(data: dict, passphrase: str) -> dict:
    Fernet, _, _, _ = _crypto()
    salt  = os.urandom(16)
    key   = _derive_fernet_key(passphrase, salt)
    token = Fernet(key).encrypt(json.dumps(data).encode())
    return {
        "v":    1,
        "salt": base64.b64encode(salt).decode(),
        "data": token.decode(),
    }

def _decrypt(stored: dict, passphrase: str) -> dict:
    Fernet, InvalidToken, _, _ = _crypto()
    salt = base64.b64decode(stored["salt"])
    key  = _derive_fernet_key(passphrase, salt)
    try:
        plain = Fernet(key).decrypt(stored["data"].encode())
    except InvalidToken:
        raise ValueError("Passphrase incorrecte — déchiffrement impossible.")
    return json.loads(plain)

def is_encrypted() -> bool:
    if not CONFIG_FILE.exists():
        return False
    try:
        d = json.loads(CONFIG_FILE.read_text())
        return d.get("v") == 1 and "salt" in d and "data" in d
    except Exception:
        return False

def verify_passphrase(passphrase: str) -> bool:
    """Vérifie qu'une passphrase déchiffre correctement la config existante."""
    if not is_encrypted():
        return True
    try:
        stored = json.loads(CONFIG_FILE.read_text())
        _decrypt(stored, passphrase)
        return True
    except Exception:
        return False

# ── gestion de la passphrase ──────────────────────────────────────────────────

def set_passphrase(p: str):
    """Injecte la passphrase depuis setup.py (évite le prompt dans la même session)."""
    global _passphrase_cache
    _passphrase_cache = p

def get_passphrase(prompt_msg: str = "  Passphrase › ") -> str | None:
    """
    Retourne la passphrase dans cet ordre :
    1. cache mémoire (session courante)
    2. variable d'env THREAT_HUNTING_PASSPHRASE (une seule tentative)
    3. prompt interactif getpass
    """
    global _passphrase_cache, _env_consumed
    if _passphrase_cache:
        return _passphrase_cache
    if not _env_consumed:
        val = os.environ.get(_ENV_VAR, "").strip()
        _env_consumed = True  # marque comme consommée, même si vide
        if val:
            return val
    try:
        pp = getpass.getpass(prompt_msg)
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    return pp or None

# ── lecture / écriture config ─────────────────────────────────────────────────

def _load_all() -> dict:
    global _data_cache
    if _data_cache is not None:
        return dict(_data_cache)

    if not CONFIG_FILE.exists():
        return {}
    try:
        raw = json.loads(CONFIG_FILE.read_text())
    except Exception:
        return {}

    if raw.get("v") == 1 and "salt" in raw and "data" in raw:
        for attempt in range(3):
            pp = get_passphrase("  Passphrase de dechiffrement › ")
            if not pp:
                print("  Passphrase requise — arrêt.", file=sys.stderr)
                sys.exit(1)
            try:
                result = _decrypt(raw, pp)
                set_passphrase(pp)  # met en cache après succès
                _data_cache = result
                return dict(_data_cache)
            except ValueError:
                global _passphrase_cache
                _passphrase_cache = None  # efface le cache pour forcer un nouveau prompt
                if attempt < 2:
                    print("  Passphrase incorrecte, reessaie.", file=sys.stderr)
        print("  Echec apres 3 tentatives — cles API inaccessibles.", file=sys.stderr)
        sys.exit(1)

    _data_cache = raw
    return dict(_data_cache)  # config plaintext (legacy / avant chiffrement)

def _save_all(data: dict):
    global _data_cache
    _data_cache = dict(data)
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    pp = get_passphrase()
    if pp:
        stored = _encrypt(data, pp)
        CONFIG_FILE.write_text(json.dumps(stored))
    else:
        CONFIG_FILE.write_text(json.dumps(data, indent=2))
    CONFIG_FILE.chmod(0o600)

# ── API publique ──────────────────────────────────────────────────────────────

_ENV_MAP = {
    "urlhaus":    "URLHAUS_API_KEY",
    "abuseipdb":  "ABUSEIPDB_API_KEY",
    "virustotal": "VIRUSTOTAL_API_KEY",
    "shodan":     "SHODAN_API_KEY",
    "censys":     "CENSYS_API_KEY",
}

def load_key(service: str) -> str | None:
    val = os.environ.get(_ENV_MAP.get(service, ""), "").strip()
    if val:
        return val
    return _load_all().get(service, "").strip() or None

def save_key_to_config(service: str, key: str):
    data = _load_all()
    data[service] = key.strip()
    _save_all(data)

def load_setting(key: str, default=None):
    """Lit un paramètre non-sensible depuis settings.json (sans passphrase)."""
    try:
        data = json.loads(SETTINGS_FILE.read_text())
        return data.get(key, default)
    except (FileNotFoundError, json.JSONDecodeError):
        return default

def save_setting(key: str, value):
    """Sauvegarde un paramètre non-sensible dans settings.json (sans passphrase)."""
    try:
        data = json.loads(SETTINGS_FILE.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        data = {}
    data[key] = value
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    SETTINGS_FILE.write_text(json.dumps(data, indent=2))

def all_keys() -> dict:
    stored = _load_all()
    result = {}
    for svc in SERVICES:
        env_val = os.environ.get(_ENV_MAP.get(svc, ""), "").strip()
        result[svc] = env_val or stored.get(svc, "").strip()
    return result

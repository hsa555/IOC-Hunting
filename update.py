#!/usr/bin/env python3
# Made by hsa5
"""
IOC Hunting — Mise à jour automatique depuis GitHub
=====================================================
Nécessite git installé et un clone du dépôt (pas un téléchargement ZIP).

Usage :
  python update.py              → vérifie et propose la mise à jour
  python update.py --check      → vérifie uniquement, sans modifier
  python update.py --rollback   → revient à la version précédente
  python update.py --list       → liste les backups disponibles
  python update.py --rollback --tag backup/20250529-143000  → rollback précis
"""

import sys
import os
import subprocess
import argparse

RESET  = "\033[0m";  BOLD  = "\033[1m";  DIM    = "\033[2m"
RED    = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
CYAN   = "\033[96m"; WHITE = "\033[97m"

def c(text, *codes): return "".join(codes) + str(text) + RESET
def sep(ch="─", w=60): print(c(ch * w, DIM))

REPO_DIR = os.path.dirname(os.path.abspath(__file__))

# ── helpers git ────────────────────────────────────────────────────────────────

def _git(*args) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", REPO_DIR, *args],
        capture_output=True, text=True,
    )

def _check_prerequisites() -> bool:
    if subprocess.run(["git", "--version"], capture_output=True).returncode != 0:
        print(c("  git n'est pas installé ou introuvable dans le PATH.", RED))
        return False
    if _git("rev-parse", "--git-dir").returncode != 0:
        print(c("  Ce répertoire n'est pas un dépôt git.", RED))
        print(c("  Clone le projet via :  git clone <url>", DIM))
        return False
    return True

def _current_info() -> tuple[str, str]:
    """Retourne (hash_court, date_iso) du commit HEAD actuel."""
    h = _git("log", "-1", "--format=%h").stdout.strip()
    d = _git("log", "-1", "--format=%ci").stdout.strip()[:16]
    return h, d

def _upstream() -> str:
    """Branche remote suivie par HEAD (ex: origin/main). Fallback: origin/main."""
    r = _git("rev-parse", "--abbrev-ref", "@{upstream}")
    if r.returncode == 0:
        return r.stdout.strip()
    return "origin/main"

def _backup_tags() -> list[str]:
    r = _git("tag", "-l", "backup/*", "--sort=-version:refname")
    return [t for t in r.stdout.strip().splitlines() if t]

# ── commandes ──────────────────────────────────────────────────────────────────

def cmd_check(fetch: bool = True) -> bool:
    """Fetch + affiche les nouveaux commits. Retourne True si une MAJ est dispo."""
    if fetch:
        print(c("  Vérification des mises à jour...", DIM), end="\r", flush=True)
        r = _git("fetch", "origin", "--quiet")
        print(" " * 55, end="\r")
        if r.returncode != 0:
            print(c(f"  Impossible de contacter GitHub : {r.stderr.strip()}", RED))
            return False

    upstream = _upstream()
    local    = _git("rev-parse", "HEAD").stdout.strip()
    remote   = _git("rev-parse", upstream).stdout.strip()

    h, d = _current_info()
    sep()
    print(f"\n  {c('Version locale', BOLD)}   {c(h, CYAN)}  {c(d, DIM)}\n")

    if local == remote:
        print(f"  {c('✓  Déjà à jour — aucune mise à jour disponible.', GREEN)}\n")
        sep()
        return False

    log = _git("log", f"HEAD..{upstream}", "--oneline", "--no-decorate").stdout.strip()
    lines = log.splitlines() if log else []
    print(f"  {c(f'{len(lines)} nouveau(x) commit(s) disponible(s) :', YELLOW, BOLD)}\n")
    for line in lines:
        sha, *msg = line.split(" ", 1)
        print(f"    {c(sha, CYAN)}  {' '.join(msg)}")
    print()
    sep()
    return True

def cmd_update():
    """Sauvegarde le commit courant puis applique git pull."""
    has_update = cmd_check(fetch=True)
    if not has_update:
        return

    try:
        ok = input(c("  Mettre à jour maintenant ? (O/n) › ", DIM)).strip().lower()
    except EOFError:
        ok = "n"
    if ok == "n":
        print(c("  Mise à jour annulée.\n", DIM))
        return

    # Backup — tag nommé d'après le hash court du commit qu'on quitte
    h_now = _git("rev-parse", "--short", "HEAD").stdout.strip()
    tag   = f"backup/{h_now}"
    if _git("tag", tag).returncode == 0:
        print(c(f"\n  Backup créé : {c(tag, CYAN)}", DIM))

    # Stash des modifications locales non committées (ex: fichiers de config édités)
    stashed = False
    r_st = _git("stash", "--quiet")
    if r_st.returncode == 0 and r_st.stdout.strip():
        stashed = True
        print(c("  Modifications locales sauvegardées (git stash).", DIM))

    # Pull
    print(c("  Téléchargement...", DIM), end="\r", flush=True)
    r_pull = _git("pull", "--ff-only")
    print(" " * 40, end="\r")

    if r_pull.returncode != 0:
        print(c(f"\n  Erreur lors de la mise à jour :\n  {r_pull.stderr.strip()}", RED))
        print(c(f"\n  Le backup {tag} est disponible (--rollback).", YELLOW))
        if stashed:
            _git("stash", "pop", "--quiet")
        return

    if stashed:
        r_pop = _git("stash", "pop", "--quiet")
        if r_pop.returncode != 0:
            print(c("  Avertissement : impossible de restaurer le stash automatiquement.", YELLOW))
            print(c("  Lance :  git stash pop  manuellement.", DIM))

    h, d = _current_info()
    print(f"\n  {c('✓  Mise à jour réussie !', GREEN, BOLD)}")
    print(f"  {c('Nouvelle version', BOLD)}  {c(h, CYAN)}  {c(d, DIM)}")
    print(c(f"\n  Pour revenir en arrière :  python update.py --rollback", DIM))
    sep()

def cmd_list():
    """Affiche les backups disponibles avec leur hash et date."""
    tags = _backup_tags()
    sep()
    if not tags:
        print(c("\n  Aucun backup disponible.\n", DIM))
    else:
        print(f"\n  {c('Backups disponibles', BOLD)}  {c(f'({len(tags)})', DIM)}\n")
        for tag in tags:
            h_at = tag.replace("backup/", "")
            dt   = _git("log", "-1", "--format=%ci", tag).stdout.strip()[:16]
            msg  = _git("log", "-1", "--format=%s",  tag).stdout.strip()[:60]
            print(f"    {c('·', DIM)}  {c(h_at, CYAN)}  {c(dt, DIM)}  {c(msg, DIM)}")
        print()
        print(c(f"  Usage : python update.py --rollback --tag <tag>", DIM))
    print()
    sep()

def cmd_rollback(tag: str = None):
    """Revient au backup le plus récent, ou au tag précisé via --tag."""
    tags = _backup_tags()

    if not tags:
        print(c("\n  Aucun backup disponible — impossible de revenir en arrière.", RED))
        print(c("  La mise à jour crée un backup automatiquement avant chaque pull.\n", DIM))
        return

    if tag:
        if tag not in tags:
            print(c(f"\n  Backup introuvable : {tag}", RED))
            cmd_list()
            return
        chosen = tag
    else:
        chosen = tags[0]

    # Affiche les infos du backup choisi
    h_at  = chosen.replace("backup/", "")
    dt    = _git("log", "-1", "--format=%ci", chosen).stdout.strip()[:16]
    h_now, d_now = _current_info()

    sep()
    print(f"\n  {c('Version actuelle', BOLD)}   {c(h_now, DIM)}  {c(d_now, DIM)}")
    print(f"  {c('Retour vers', BOLD)}        {c(h_at, CYAN)}  {c(dt, DIM)}\n")

    if len(tags) > 1:
        print(c(f"  Autres backups : {len(tags) - 1} disponible(s) (--list pour voir tous).", DIM))
        print()

    try:
        ok = input(c("  Confirmer le rollback ? (O/n) › ", DIM)).strip().lower()
    except EOFError:
        ok = "n"
    if ok == "n":
        print(c("  Rollback annulé.\n", DIM))
        return

    r = _git("reset", "--hard", chosen)
    if r.returncode != 0:
        print(c(f"\n  Erreur : {r.stderr.strip()}", RED))
        return

    # Supprime le tag utilisé pour éviter de rollback deux fois au même endroit
    _git("tag", "-d", chosen)

    h, d = _current_info()
    print(f"\n  {c('✓  Rollback effectué.', GREEN, BOLD)}")
    print(f"  {c('Version restaurée', BOLD)}  {c(h, CYAN)}  {c(d, DIM)}\n")
    sep()

# ── main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="update",
        description="IOC Hunting — Mise à jour automatique depuis GitHub",
    )
    parser.add_argument("--check",    action="store_true",
                        help="Vérifie si une mise à jour est disponible (sans modifier)")
    parser.add_argument("--rollback", action="store_true",
                        help="Revient à la version précédente (dernier backup)")
    parser.add_argument("--list",     action="store_true",
                        help="Liste tous les backups disponibles")
    parser.add_argument("--tag",      metavar="BACKUP_TAG",
                        help="Tag de backup cible pour --rollback (voir --list)")
    args = parser.parse_args()

    print()
    print(c("  ╔═══════════════════════════════════════╗", CYAN))
    print(c("  ║  ", CYAN) + c("IOC Hunting", BOLD, WHITE) + c(" — Mise à jour              ║", CYAN))
    print(c("  ╚═══════════════════════════════════════╝", CYAN))
    print()

    if not _check_prerequisites():
        sys.exit(1)

    if args.list:
        cmd_list()
    elif args.check:
        cmd_check()
    elif args.rollback:
        cmd_rollback(args.tag)
    else:
        cmd_update()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {c('Ctrl+C — Au revoir.', YELLOW)}\n")
        sys.exit(0)

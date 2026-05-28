## 2026-05-28 (refactor & optimisations)
- `setup.py` : option reset complet (passphrase oubliée) accessible sans passphrase + proposé automatiquement après 3 échecs
- `config_loader.py` : import crypto lazy, cache settings, `_ENV_MAP` fusionné dans `SERVICES`
- Modules : suppressions de doublons et redondances mineures dans `setup.py`, `config_loader.py`, `main.py` et les modules standalone

## 2026-05-22 (fixes)
- Passphrase vide (Entrée sans saisir) → arrêt immédiat du script au lieu de continuer sans clés
- Bouton scroll-to-top : fond bleu + bordure accent + halo, taille 48px — plus visible sur fond sombre

## 2026-05-22 (web — améliorations UI)
- Interface web : textarea multi-lignes — plusieurs cibles saisies une par ligne
- Upload `.txt` : bouton "Charger .txt", une cible par ligne, `#` = commentaire
- Résultats : une carte séparée par cible au lieu d'un seul bloc monolithique
- Nav de navigation (chips cliquables) affiché au-dessus des cartes en mode multi-cibles
- Bouton `↓ JSON` pour télécharger tous les résultats en JSON (Blob URL côté client)
- Entrées malformées (`1.2.3.4 5.6.7.8` sur une ligne) : erreur immédiate, jamais mises en cache
- Option `w` dans le menu interactif (`python3 main.py`) pour lancer l'interface web

## 2026-05-22 (web)
- Interface web locale `--web` : bind uniquement sur 127.0.0.1, jamais exposé sur le réseau
- Protection CSRF sur chaque POST (token aléatoire généré au lancement)
- Détection de conflit de port au lancement, port configurable via `setup.py`
- Sortie terminal (ANSI) convertie en HTML coloré dans l'interface
- Historique des 10 dernières analyses persisté dans `localStorage`
- Suppression des logs Werkzeug pour garder le terminal propre
- Flask ajouté dans `requirements.txt` (optionnel, uniquement pour `--web`)

## 2026-05-22
- `setup.py` affiche un menu (passphrase / clés API / cache / tout) quand la config existe déjà, au lieu de repasser sur chaque étape
- Cache des résultats avec durée configurable via `setup.py` (24h par défaut, Entrée pour valider) — supporte `h`, `j`, `sem` (ex: `48h`, `2j`, `1sem`)
- Écriture atomique du cache (`.tmp` + `os.replace`) — plus de corruption sur Ctrl+C
- Purge automatique au lancement des entrées expirées (> 24h)
- Avertissement + prompt de vidage si le cache dépasse 500 entrées
- Option `--nocache` pour forcer des requêtes API fraîches
- Tab completion sur les inputs de chemin (fichier / répertoire / export)
- Tags VirusTotal affichés inline sur la ligne de résumé (`| Tags : scanner, vpn`)

## Initial
- Corrélation multi-sources IP/URL : AbuseIPDB · VirusTotal · Shodan · Censys · URLhaus
- Mode Hash : VirusTotal + URLhaus (MD5 / SHA1 / SHA256)
- Score de menace agrégé 0–100 (FAIBLE / MODÉRÉ / ÉLEVÉ / CRITIQUE)
- Hachage local de fichiers et scan de répertoire
- Chiffrement des clés API (Fernet/PBKDF2)
- Fallback automatique Shodan → InternetDB sans clé
- Export JSON, sortie JSON brute, filtre par année VT
- Scripts standalone par source

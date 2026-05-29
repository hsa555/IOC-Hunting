## 2026-05-29
- Google Dorks : les requêtes SerpAPI sont lancées en parallèle — analyse plus rapide
- Délai VirusTotal configurable via `setup.py` — le mettre à 0 supprime les pauses avec une clé payante
- Fichiers de clés, cache et paramètres créés directement en permissions 600
- Interface web : taille d'upload limitée et nombre de cibles plafonné par analyse
- Cache des résultats écrit une seule fois par lot — plus rapide sur les grandes listes
- Un pourcentage VirusTotal non numérique ne fait plus planter l'affichage
- Setup : choix chiffrer ou non les clés API au premier lancement, activable/désactivable ensuite depuis le menu
- Setup : saisie des clés API visible (plus de masquage Censys)
- Support des domaines (evil.com) en plus des IPs et URLs
- Support IPv6
- Export CSV avec `--export rapport.csv`
- Mode silencieux `--quiet` avec code retour basé sur le score (pour scripts/pipelines)
- Lecture depuis stdin avec `--file -`
- Déduplication automatique des cibles
- `update.py` : mise à jour depuis GitHub avec rollback possible
- Google Dorks demandé une seule fois au début, pas après chaque IP
- GreyNoise : détecte si une IP scanne internet (scanner légitime, malveillant, service connu) — sans clé requise
- MalwareBazaar : famille, tags comportementaux, méthode de livraison et vendor intel sur les hashes — même clé qu'URLhaus
- Barre de progression en bas du terminal lors de l'analyse de listes
- URLs scannées via VT + URLhaus + AbuseIPDB sur l'IP du host si applicable

## 2026-05-28 (Google Dorks)
- Nouveau module `modules/googledorks_lookup.py` : recherche Google via SerpAPI (100 req/mois gratuit)
- Intégré dans `main.py` : prompt "Google Dorks ? (o/N)" après chaque analyse IP interactive
- 3 requêtes SerpAPI par analyse : page 1 (start=0) + page 2 (start=10) + sous-réseau /24
- Résultats triés par pertinence CTI (botnet, malware, phishing, APT, C2… remontent en premier)
- Exclusion à deux niveaux : `-site:` operators dans la requête + post-filtre liste complète (~90 domaines)
- Clé SerpAPI configurable via `setup.py` (stockée chiffrée comme les autres clés)
- `googledorks_lookup.py` standalone : `python3 modules/googledorks_lookup.py <ip> [--num N] [--json]`

## 2026-05-28 (URLhaus & VT)
- Payloads URLhaus : badge online/offline, filtre online-only par défaut, `--offline` pour tout afficher
- VT rate limit : fenêtre glissante pour mieux gérer les listes de plusieurs IPs

## 2026-05-28 (refactor)
- Reset complet de la config accessible sans passphrase (pratique si passphrase oubliée)
- Optimisations internes config_loader et suppressions de doublons dans les modules

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

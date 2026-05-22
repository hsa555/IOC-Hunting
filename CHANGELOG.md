## 2026-05-22
- Cache des résultats 24h glissantes (`~/.config/threat_hunting/cache.json`) — évite de reconsommer du quota API sur les cibles récentes
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

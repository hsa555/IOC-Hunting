## 2026-05-22
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

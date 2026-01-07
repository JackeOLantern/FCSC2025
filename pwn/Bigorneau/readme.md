# FCSC 2025 — Bigorneau (pwn x86_64)

Ce dépôt regroupe les fichiers du challenge **Bigorneau** (FCSC 2025) et une description reproductible de la résolution.

## Fichiers fournis

- `bigorneau` : exécutable qui charge un blob binaire (shellcode) depuis un fichier et l’exécute.
- `bigorneau.c` : source C du lanceur, compilé avec pile exécutable (`-z execstack`).
- `bigorneau.py` : *script d’interface (côté challenge) qui impose les contraintes et exécute `./bigorneau`*.
- `docker-compose.yml` : *fourni sur Hackropole pour exécuter l’épreuve localement*.
- Captures d’écran (Hackropole / FCSC) : voir `Capture d’écran 2025-05-02 181109.png` et `Capture d’écran 2025-05-02 181507.png`.

> Note : dans cette session, seuls `bigorneau`, `bigorneau.c`, le document Word et les captures étaient présents.  
> Si tu veux que le README cite **mot pour mot** `bigorneau.py` et/ou `docker-compose.yml`, il faut les (re)joindre au dépôt.

## Pré-requis

- Docker + Docker Compose (exécution locale via Hackropole)
- Python 3 (interaction / génération de payload)
- Outils utiles : `objdump`, `readelf`, `gdb`, `pwntools` (optionnel)

## Exécution locale (Hackropole)

1. Télécharger le `docker-compose.yml` indiqué dans l’énoncé Hackropole.
2. Lancer le service :
   ```bash
   docker compose up
   ```
3. Dans un second terminal :
   ```bash
   nc localhost 4000
   ```

Pour l’instance distante FCSC (selon l’énoncé) :
```bash
nc chall.fcsc.fr 2102
```

## TL;DR de la solution

- Le service attend un **shellcode x86_64** fourni en **hexadécimal**.
- Contrainte principale : `len(set(shellcode)) <= 6` (au plus **6 valeurs d’octets distinctes** dans *le shellcode utilisateur*).
- Le wrapper Python (côté challenge) **préfixe** le shellcode par une séquence qui remet des registres à zéro, puis exécute `./bigorneau`.
- La résolution consiste à envoyer un **stage 0** extrêmement restreint (≤6 octets distincts) qui reconstruit en mémoire un **stage 1** “normal” (syscalls `open/read/write`) pour lire `/flag` et l’afficher.

## Flag

Le flag validé (fichier `fcsc_pwn_bigorneau.txt`) :

`FCSC{619c629f9dd846fe8f1db9f23693707b7a334ab7da1507dc904b9d5c3fc2a15c}`

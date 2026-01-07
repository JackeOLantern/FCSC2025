# Write-up — Bigorneau (FCSC 2025, pwn)

## 1. Énoncé et objectif

Le challenge demande de fournir un shellcode **x86_64** mais avec une contrainte inhabituelle :

> vous ne pouvez utiliser que **6 valeurs d’octets distinctes**  
> (i.e. `len(set(shellcode)) <= 6`)

L’objectif pratique est d’exécuter du code arbitraire pour **afficher le contenu du fichier de flag** (typiquement `/flag`) via des syscalls.

## 2. Analyse des fichiers

### 2.1 `bigorneau.c` (exécuteur de shellcode)

Le programme :

1. lit un fichier contenant jusqu’à 1024 octets,
2. copie ces octets en mémoire (buffer sur la pile),
3. caste ce buffer en pointeur de fonction et l’exécute.

Le commentaire de compilation (`-z execstack`) indique explicitement que la pile est exécutable : c’est un *runner* volontairement vulnérable.

### 2.2 `bigorneau.py` (interface / contraintes)

Le script Python (côté challenge) :

1. demande un shellcode en hex (≤128 octets),
2. impose `len(set(shellcode)) <= 6`,
3. préfixe le shellcode par des instructions de “nettoyage” (mise à zéro de registres),
4. écrit le blob en fichier temporaire (`/dev/shm/...`),
5. exécute `./bigorneau <fichier>`.

Point clé : la contrainte “6 octets distincts” s’applique **au shellcode utilisateur** (la partie saisie), pas forcément au préfixe ajouté par le wrapper.

## 3. Démarche de résolution (payload final)

1. Lancer l’instance (Docker : `docker compose up`, puis `nc localhost 4000` côté client).
2. Entrée attendue : une ligne hex → shellcode utilisateur (≤128 octets, ≤6 octets distincts).
3. Contexte : le wrapper remet les registres à zéro puis exécute le blob.
4. Choix “2-stages” minimal :
   - **Stage 0** (8 octets, 6 valeurs distinctes) : `545eb2540f0554c3`  
     Lit 0x54 octets sur stdin (stage 1) dans la pile, puis `ret` dessus.
   - **Stage 1** (0x54 octets) : shellcode `open("/flag",0)` → `read` → `write`, padded en NOP.
5. Envoi : ligne hex du stage0, courte pause pour laisser `input()` finir, puis flux binaire du stage1.
6. Résultat : le stage1 imprime le flag sur stdout (extrait automatiquement par le solveur).

## 4. Points d’attention / debugging

- Bien séparer la ligne hex (stage0) du flux binaire (stage1) pour éviter que `input()` ne lise des octets binaires.
- Respect strict de `len(set(stage0)) <= 6`.
- Padding du stage1 à 0x54 octets pour matcher la longueur lue par le stage0.
- Envoi manuel possible : `printf '545eb2540f0554c3\n'` puis stream du stage1 binaire (généré via `build_stage1` dans `solve.py`).
 - Le stage1 écrit seulement le nombre d’octets réellement lus (`mov rdx, rax` avant `write`) pour éviter l’affichage de padding.

## 5. Flag

`FCSC{619c629f9dd846fe8f1db9f23693707b7a334ab7da1507dc904b9d5c3fc2a15c}`

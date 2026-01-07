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

## 3. Démarche de résolution (≤ 10 étapes)

1. **Lancer l’instance** (Docker local ou `nc chall.fcsc.fr 2102`).
2. **Identifier le format d’entrée** : une chaîne hexadécimale représentant les octets du shellcode.
3. **Confirmer les contraintes** : taille (≤128) et diversité d’octets (≤6).
4. **Exploiter le contexte connu** : le wrapper remet les registres à zéro, donc on part d’un état initial stable.
5. **Choisir une stratégie “2-stages”** :
   - *Stage 0* : mini-décodeur utilisant ≤6 valeurs d’octets.
   - *Stage 1* : shellcode standard qui effectue `open/read/write` sur `/flag`.
6. **Encoder le Stage 1** (ex. XOR/ADD, ou écriture octet-par-octet) pour que le Stage 0 puisse le reconstruire.
7. **Envoyer le Stage 0 + données encodées** en respectant strictement `len(set(stage0_bytes)) <= 6`.
8. **Exécution** : le runner charge le blob et exécute : Stage 0 reconstruit Stage 1 puis branche dessus.
9. **Récupérer la sortie** : le Stage 1 imprime le flag sur `stdout`.
10. **Soumettre le flag** sur la plateforme.

## 4. Points d’attention / debugging

- Si le décodage est instable, vérifier :
  - l’alignement et l’adresse RIP-relative utilisée par le Stage 0,
  - la longueur exacte reconstruite,
  - la présence de caractères `\n` dans l’entrée hex (côté netcat).
- Pour itérer rapidement : tester en local (docker) puis valider sur remote.

## 5. Flag

`FCSC{619c629f9dd846fe8f1db9f23693707b7a334ab7da1507dc904b9d5c3fc2a15c}`

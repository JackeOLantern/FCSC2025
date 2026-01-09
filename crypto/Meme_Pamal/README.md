# Même Pamal — FCSC 2025 (Crypto / Courbe elliptique)

Ce dépôt contient une résolution **pure Python** du challenge **« Même Pamal »** (FCSC 2025), à partir des deux fichiers fournis :

- `meme-pamal.py` : générateur Sage (paramètres de courbe + chiffrement)
- `output.txt` : sortie JSON contenant `pk` et la liste `enc`

## TL;DR (idée)

Le chiffrement est un ElGamal sur courbe elliptique, byte-par-byte :

- `u = r·G`
- `v = T(m) + r·PK`

où `G` a un **ordre premier** `order` et `PK = sk·G`.  
Or `r·PK` vit **dans le sous-groupe** `<G>` d’ordre `order`. Donc :

`order·v = order·T(m) + order·(r·PK) = order·T(m)`

Le masque disparaît en multipliant **uniquement `v`** par `order`.

Comme `m` est un octet, on pré-calcule un dictionnaire :

`m -> order·T(m)` pour `m ∈ [0..255]`, puis on déchiffre par lookup.

## Lancer le solveur

```bash
python3 solve_meme_pamal.py --chal meme-pamal.py --out output.txt
```

Option verbeuse :

```bash
python3 solve_meme_pamal.py --chal meme-pamal.py --out output.txt -v
```

## Dépendances

- Python 3.10+ (aucune lib externe)

## Fichiers

- `solve_meme_pamal.py` : solveur complet
- `writeup.md` : explication détaillée de l’attaque

# Write-up — Même Pamal (FCSC 2025)

## 1. Ce que fait le code

Le fichier `meme-pamal.py` instancie une courbe elliptique courte de Weierstrass :

- Champ :  `K = GF(p)` (p premier)
- Courbe : `E : y^2 = x^3 + x`  (paramètres `[1,0]`)
- Générateur : `G`
- Sous-groupe cyclique : `<G>` d’ordre `order` (grand premier)

La clé privée et publique :

- `sk ← [0..order-2]`
- `PK = sk·G`

L’encodage d’un octet `m` :

- `step = 128`
- on prend `x = m·step`, puis on incrémente `x` jusqu’à ce que `x` soit un `x` valide sur la courbe (`lift_x`)
- on obtient un point `T(m) ∈ E(F_p)`
- la fonction `decode` renvoie `⌊x/step⌋` (on retrouve `m`)

Le chiffrement (par octet) :

- `r ← [0..order-2]`
- `u = r·G`
- `v = T(m) + r·PK`
- le chiffré est `(u, v)`

C’est donc un ElGamal ECC classique… sauf un détail crucial sur `T(m)`.

## 2. Propriété clé : le masque est dans un sous-groupe

`G` a l’ordre `order`, donc **tout multiple de `G`** (et donc de `PK = sk·G`) vit dans le sous-groupe `<G>` d’ordre `order`.

En particulier, pour n’importe quel `r` :

- `r·PK ∈ <G>`
- donc `order·(r·PK) = O` (point à l’infini), car `order` annule `<G>`

## 3. L’attaque : multiplier `v` par `order`

On part de :

`v = T(m) + r·PK`

On multiplie des deux côtés par `order` :

`order·v = order·T(m) + order·(r·PK)`

Or `order·(r·PK) = O`, donc :

`order·v = order·T(m)`

On vient d’éliminer complètement le masque `r·PK` **sans connaître `sk`**, ni `r`, ni résoudre de logarithme discret.

## 4. Récupérer l’octet (lookup)

Comme `m` est un octet, il n’y a que 256 possibilités.

On peut donc pré-calculer :

Pour chaque `m ∈ [0..255]` :
1. calculer `T(m)` comme dans le challenge (lift_x avec step=128)
2. calculer `Pm = order·T(m)`
3. stocker `Pm -> m` (et aussi `-Pm -> m` pour gérer le choix de racine carrée)

Ensuite, pour chaque chiffré `(u,v)` :
1. calculer `P = order·v`
2. retrouver `m` via le dictionnaire
3. concaténer tous les octets

Complexité : ~256 + len(flag) multiplications scalaires (ici ~326), donc très rapide.

## 5. Flag

En appliquant l’attaque au fichier `output.txt` :

`FCSC{b8e2a388a77944f15bc9d2b1bcb347d58ec9cb9007882a79d04b892acc413456}`

## 6. Remarque sécurité

Ce type de vulnérabilité est une conséquence directe du fait que le message `T(m)` n’est pas forcé dans le même sous-groupe que le générateur `G`.

En pratique, il faut :
- travailler dans un groupe **d’ordre premier** (cofacteur 1) ou
- faire du **cofactor clearing** / encodage dans le sous-groupe cible, ou
- utiliser un schéma de chiffrement/encapsulation standard (ECIES/KEM) plutôt qu’un encodage ad-hoc de points.

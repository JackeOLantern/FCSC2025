#!/usr/bin/env python3
"""
FCSC 2025 — Crypto / Courbe elliptique — "Même Pamal"
Solveur **pure Python** (sans Sage).
Auteur(e) : JG
Contexte
--------
Le challenge chiffre le flag octet par octet via un schéma type ElGamal ECC :

    u = r·G
    v = T(m) + r·PK

où :
- E : y^2 = x^3 + x sur F_p
- G est un point de **sous-groupe** cyclique d’ordre premier `order`
- PK = sk·G
- T(m) est un encodage "lift_x" (message -> point) pour l'octet m

Observation clé (attaque)
-------------------------
Le masque r·PK appartient au sous-groupe <G> d’ordre `order`, donc :

    order·(r·PK) = O

Ainsi :

    order·v = order·T(m) + order·(r·PK) = order·T(m)

Le masquage disparaît en multipliant **uniquement v** par `order`.

Comme m ∈ [0..255], on pré-calcule un dictionnaire :
    m  ->  order·T(m)
et on déchiffre par lookup.

Usage
-----
    python3 solve_meme_pamal.py --chal meme-pamal.py --out output.txt
    python3 solve_meme_pamal.py --chal meme-pamal.py --out output.txt -v

Le mode `-v/--verbose` affiche les étapes intermédiaires (paramètres, pré-calcul, et
détails de déchiffrement octet par octet).
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from typing import Dict, Optional, Tuple, List

# --- Types de points ---------------------------------------------------------

Point = Optional[Tuple[int, int]]   # point affine (x, y) ; None = point à l'infini
JPoint = Tuple[int, int, int]       # point Jacobien (X, Y, Z) ; Z=0 => infini


# --- Logging / Verbose -------------------------------------------------------

@dataclass
class VerboseConfig:
    """Configuration globale du mode verbeux."""
    enabled: bool = False


V = VerboseConfig(False)


def vlog(msg: str) -> None:
    """
    Affiche un message si le mode verbose est activé.
    On centralise ici l’affichage pour garder le code propre.
    """
    if V.enabled:
        print(msg)


# --- Parsing des paramètres du challenge ------------------------------------

def parse_params(chal_py: str) -> Tuple[int, int, int, int]:
    """
    Extrait (p, gx, gy, order) depuis le fichier `meme-pamal.py`.

    Le fichier est un script Sage, mais ses constantes sont écrites en clair, ex :
        p = 0x...
        order = 0x...
        g = E(0x..., 0x...)

    Retour :
        p     : premier du corps F_p
        gx,gy : coordonnées du point générateur G
        order : ordre du sous-groupe <G>
    """
    txt = open(chal_py, "r", encoding="utf-8").read()

    # On capture les valeurs hexadécimales telles qu'elles apparaissent dans le fichier.
    p_m = re.search(r"^\s*p\s*=\s*0x([0-9a-fA-F]+)\s*$", txt, re.M)
    o_m = re.search(r"^\s*order\s*=\s*0x([0-9a-fA-F]+)\s*$", txt, re.M)
    g_m = re.search(
        r"^\s*g\s*=\s*E\(\s*0x([0-9a-fA-F]+)\s*,\s*0x([0-9a-fA-F]+)\s*\)\s*$",
        txt,
        re.M,
    )

    if not (p_m and o_m and g_m):
        raise ValueError(
            "Impossible de parser p/g/order depuis le fichier challenge. "
            "Vérifiez le format de meme-pamal.py."
        )

    p = int(p_m.group(1), 16)
    order = int(o_m.group(1), 16)
    gx = int(g_m.group(1), 16)
    gy = int(g_m.group(2), 16)

    vlog("[+] Paramètres extraits depuis meme-pamal.py")
    vlog(f"    p     = 0x{p:x}  (bits={p.bit_length()})")
    vlog(f"    order = 0x{order:x}  (bits={order.bit_length()})")
    vlog(f"    G     = (0x{gx:x}, 0x{gy:x})")

    return p, gx, gy, order


def load_output(out_json: str) -> dict:
    """
    Charge `output.txt` (JSON) qui contient typiquement :
      - pk  : la clé publique (non nécessaire pour l’attaque)
      - enc : liste de couples (u, v), chaque point en coordonnées Jacobiennes
              stockées comme triplets (X, Y, Z)

    Retour : dictionnaire Python.
    """
    data = json.loads(open(out_json, "r", encoding="utf-8").read())
    vlog("[+] Fichier output chargé")
    if V.enabled:
        vlog(f"    clés JSON = {list(data.keys())}")
        if "enc" in data:
            vlog(f"    nombre de blocs = {len(data['enc'])}")
    return data


# --- Corps fini F_p : symboles / racines carrées mod p -----------------------

def legendre_symbol(a: int, p: int) -> int:
    """
    Symbole de Legendre (a|p) pour p premier impair.

    Retour :
        1  si a est résidu quadratique mod p (a = y^2 mod p)
        -1 si a est non-résidu
        0  si a == 0 mod p
    """
    ls = pow(a % p, (p - 1) // 2, p)
    return -1 if ls == p - 1 else ls


def tonelli_shanks(n: int, p: int) -> Optional[int]:
    """
    Tonelli-Shanks : calcule y tel que y^2 ≡ n (mod p) pour p premier impair.

    Retour :
        y (une des deux racines) si n est un résidu quadratique,
        None sinon.

    Note :
        Cette fonction est appelée souvent (pré-calcul de 256 octets),
        donc elle reste silencieuse même en mode verbose (sinon spam).
    """
    n %= p
    if n == 0:
        return 0
    if p == 2:
        return n
    if legendre_symbol(n, p) != 1:
        return None

    # Cas rapide si p ≡ 3 (mod 4)
    if p % 4 == 3:
        y = pow(n, (p + 1) // 4, p)
        return y if (y * y) % p == n else None

    # Décomposition p-1 = q * 2^s (q impair)
    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1

    # Trouver un non-résidu quadratique z
    z = 2
    while legendre_symbol(z, p) != -1:
        z += 1

    c = pow(z, q, p)
    x = pow(n, (q + 1) // 2, p)
    t = pow(n, q, p)
    m = s

    while t != 1:
        # Trouver le plus petit i : t^(2^i) == 1
        i = 1
        t2i = (t * t) % p
        while i < m and t2i != 1:
            t2i = (t2i * t2i) % p
            i += 1
        b = pow(c, 1 << (m - i - 1), p)
        x = (x * b) % p
        t = (t * b * b) % p
        c = (b * b) % p
        m = i

    return x


# --- Courbe elliptique : y^2 = x^3 + a x + b avec a=1, b=0 ------------------

A_CURVE = 1  # paramètre a ; b=0 implicite


def on_curve(P: Point, p: int) -> bool:
    """
    Vérifie l'équation de la courbe pour un point affine P sur F_p.
    """
    if P is None:
        return True
    x, y = P
    return (y * y - (x * x * x + A_CURVE * x)) % p == 0


# --- Représentation Jacobienne (pour accélérer add/double/mul) ---------------

def jacobian_from_affine(P: Point, p: int) -> JPoint:
    """
    Convertit un point affine (x,y) en Jacobien (X,Y,Z) :
        (x,y) -> (x, y, 1)
    et None (infini) -> (0,1,0)
    """
    if P is None:
        return (0, 1, 0)
    x, y = P
    return (x % p, y % p, 1)


def affine_from_jacobian(P: JPoint, p: int) -> Point:
    """
    Convertit un point Jacobien en affine.
    Si Z==0, c'est le point à l'infini.
    """
    X, Y, Z = P
    if Z == 0:
        return None

    # x = X / Z^2 ; y = Y / Z^3 (dans F_p)
    z2 = (Z * Z) % p
    z3 = (z2 * Z) % p
    inv_z2 = pow(z2, -1, p)
    inv_z3 = pow(z3, -1, p)
    x = (X * inv_z2) % p
    y = (Y * inv_z3) % p
    return (x, y)


def jacobian_double(P: JPoint, p: int) -> JPoint:
    """
    Doublement de point en Jacobien.
    Formules standards pour courbe courte de Weierstrass.
    """
    X1, Y1, Z1 = P
    if Z1 == 0 or Y1 == 0:
        return (0, 1, 0)

    y1sq = (Y1 * Y1) % p
    S = (4 * X1 * y1sq) % p

    X1sq = (X1 * X1) % p
    Z1sq = (Z1 * Z1) % p
    Z1four = (Z1sq * Z1sq) % p
    M = (3 * X1sq + A_CURVE * Z1four) % p

    X3 = (M * M - 2 * S) % p
    y1four = (y1sq * y1sq) % p
    Y3 = (M * (S - X3) - 8 * y1four) % p
    Z3 = (2 * Y1 * Z1) % p
    return (X3, Y3, Z3)


def jacobian_add(P: JPoint, Q: JPoint, p: int) -> JPoint:
    """
    Addition de deux points en Jacobien.

    Gère les cas particuliers :
    - P = O ou Q = O
    - P = ±Q
    """
    X1, Y1, Z1 = P
    X2, Y2, Z2 = Q

    if Z1 == 0:
        return (X2, Y2, Z2)
    if Z2 == 0:
        return (X1, Y1, Z1)

    Z1Z1 = (Z1 * Z1) % p
    Z2Z2 = (Z2 * Z2) % p
    U1 = (X1 * Z2Z2) % p
    U2 = (X2 * Z1Z1) % p
    Z1_cub = (Z1Z1 * Z1) % p
    Z2_cub = (Z2Z2 * Z2) % p
    S1 = (Y1 * Z2_cub) % p
    S2 = (Y2 * Z1_cub) % p

    H = (U2 - U1) % p
    r = (S2 - S1) % p
    if H == 0:
        if r == 0:
            return jacobian_double(P, p)  # P == Q
        return (0, 1, 0)                 # P == -Q

    HH = (H * H) % p
    HHH = (HH * H) % p
    Vv = (U1 * HH) % p

    X3 = (r * r - HHH - 2 * Vv) % p
    Y3 = (r * (Vv - X3) - S1 * HHH) % p
    Z3 = (H * Z1 * Z2) % p
    return (X3, Y3, Z3)


def jacobian_neg(P: JPoint, p: int) -> JPoint:
    """
    Négation d'un point Jacobien : (X, Y, Z) -> (X, -Y, Z).
    """
    X, Y, Z = P
    if Z == 0:
        return P
    return (X, (-Y) % p, Z)


def jacobian_mul(P: JPoint, n: int, p: int) -> JPoint:
    """
    Multiplication scalaire (double-and-add) en Jacobien.

    - Supporte n négatif via la négation.
    - Complexité O(log n) additions/doublements.
    """
    if n == 0 or P[2] == 0:
        return (0, 1, 0)
    if n < 0:
        return jacobian_mul(jacobian_neg(P, p), -n, p)

    R = (0, 1, 0)  # accumulateur (point à l'infini)
    Q = P          # "base" courante

    while n:
        if n & 1:
            R = jacobian_add(R, Q, p)
        Q = jacobian_double(Q, p)
        n >>= 1

    return R


# --- Encodage "lift_x" du challenge -----------------------------------------

STEP = 128  # identique au challenge


def lift_x(x: int, p: int) -> Optional[Point]:
    """
    Reproduit E.lift_x(x) (Sage) sur la courbe y^2 = x^3 + x.

    Pour un x donné, on calcule rhs = x^3 + x et on tente de trouver y :
        y^2 = rhs (mod p)

    Retour :
        (x, y) si une racine carrée existe,
        None sinon.
    """
    rhs = (pow(x, 3, p) + A_CURVE * x) % p
    y = tonelli_shanks(rhs, p)
    if y is None:
        return None
    return (x % p, y)


def encode_byte(m: int, p: int) -> Tuple[Point, int]:
    """
    Encodage d’un octet m comme dans le challenge :

    x = m*STEP
    tant que lift_x(x) échoue : x += 1
    retourne le point lifté

    Retour :
        (point, nb_increments)
    """
    x = m * STEP
    inc = 0
    while True:
        P = lift_x(x, p)
        if P is not None:
            return P, inc
        x += 1
        inc += 1


def build_lookup(p: int, order: int) -> Dict[Point, int]:
    """
    Construit la table de correspondance :
        order·T(m)  ->  m

    Important :
    - Sage choisit arbitrairement une des deux racines y.
      Tonelli-Shanks peut retourner l’autre racine.
    - Pour être robuste, on stocke aussi le point opposé -Pm.

    Verbose :
    - affiche des statistiques sur le nombre d'incréments nécessaires
      lors du lift (certaines valeurs de m requièrent x=m*STEP+delta).
    """
    vlog("[+] Pré-calcul LUT : m -> order·T(m) (256 valeurs)")
    lut: Dict[Point, int] = {}

    total_inc = 0
    max_inc = 0
    max_inc_m = 0
    nonzero: List[Tuple[int, int]] = []

    for m in range(256):
        t, inc = encode_byte(m, p)
        total_inc += inc
        if inc > 0:
            nonzero.append((m, inc))
        if inc > max_inc:
            max_inc = inc
            max_inc_m = m

        Tj = jacobian_from_affine(t, p)
        Pj = jacobian_mul(Tj, order, p)
        Pm = affine_from_jacobian(Pj, p)

        # Stockage direct
        lut[Pm] = m
        # Stockage de -Pm pour gérer le choix de racine carrée
        if Pm is not None:
            lut[(Pm[0], (-Pm[1]) % p)] = m

        if V.enabled and (m % 32 == 0):
            vlog(f"    ... {m:3d}/255 (inc={inc})")

    if V.enabled:
        avg = total_inc / 256.0
        vlog("[+] LUT prête")
        vlog(f"    increments: total={total_inc}, moyenne={avg:.3f}, max={max_inc} (m={max_inc_m})")
        if nonzero:
            # On affiche un extrait (sans flood)
            sample = ", ".join([f"{m}:{inc}" for m, inc in nonzero[:16]])
            tail = " ..." if len(nonzero) > 16 else ""
            vlog(f"    m nécessitant x+=delta (extrait): {sample}{tail}")

    return lut


# --- Déchiffrement -----------------------------------------------------------

def solve(chal_py: str, out_json: str, verbose: bool = False) -> bytes:
    """
    Déchiffre le flag depuis :
      - le fichier challenge (pour p/order/G)
      - le fichier output (pour enc)

    Étapes (mode verbose) :
      1. Parse des paramètres de courbe
      2. Chargement JSON output
      3. Construction de la LUT (256 points)
      4. Pour chaque bloc (u, v) :
         - calcul P = order·v (annule le masque)
         - lookup -> m
         - affichage des valeurs intermédiaires
    """
    V.enabled = verbose

    # 1) Paramètres de courbe
    p, gx, gy, order = parse_params(chal_py)

    # 2) Sortie JSON
    data = load_output(out_json)
    enc = data["enc"]

    # 3) LUT de messages
    lut = build_lookup(p, order)

    # 4) Déchiffrement bloc par bloc
    vlog("[+] Déchiffrement : pour chaque (u,v), calculer order·v et faire un lookup")
    out: List[int] = []

    for i, (u, v) in enumerate(enc):
        # Remarque : u n’est pas nécessaire pour l’attaque ; on le garde pour le format.
        vx, vy, vz = map(int, v)
        Vaff: Point = (vx, vy)

        if not on_curve(Vaff, p):
            raise ValueError(f"Bloc {i}: v n'est pas sur la courbe (données corrompues ?)")

        Vj = jacobian_from_affine(Vaff, p)

        # Étape clé : P = order·v = order·T(m)
        Pj = jacobian_mul(Vj, order, p)
        Pi = affine_from_jacobian(Pj, p)

        m = lut.get(Pi)
        if m is None:
            # Diagnostic avancé si l’entrée LUT est manquante
            raise ValueError(
                f"Lookup impossible au bloc {i}. "
                f"Point P = {Pi}. (Cela ne devrait pas arriver.)"
            )

        out.append(m)

        if V.enabled:
            # Affichage complet des étapes intermédiaires, bloc par bloc
            ch = chr(m) if 32 <= m <= 126 else "."
            vlog(f"    [{i:03d}] v_aff=(0x{vx:x}, 0x{vy:x})  -> P=order·v = {Pi}  -> m={m:3d} ('{ch}')")

    flag = bytes(out)
    vlog("[+] Déchiffrement terminé")
    vlog(f"    longueur={len(flag)} octets")

    return flag


def main() -> None:
    """
    Point d'entrée CLI.
    -v active l’affichage des étapes intermédiaires.
    """
    ap = argparse.ArgumentParser(description="Solveur FCSC 2025 — Même Pamal (ECC)")
    ap.add_argument("--chal", default="meme-pamal.py", help="Chemin vers meme-pamal.py (challenge)")
    ap.add_argument("--out", default="output.txt", help="Chemin vers output.txt (JSON)")
    ap.add_argument("-v", "--verbose", action="store_true", help="Affiche les étapes intermédiaires")
    args = ap.parse_args()

    flag = solve(args.chal, args.out, args.verbose)

    # Affichage final
    try:
        print(flag.decode())
    except UnicodeDecodeError:
        print(flag)


if __name__ == "__main__":
    main()

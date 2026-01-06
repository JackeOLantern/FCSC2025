# Grand Classic Hotel — MIFARE Classic (Trace → Clé → Flag)

**But** : à partir d’une trace Proxmark3 (`.trace`), dériver la/les clé(s) sectorielles MIFARE Classic et retrouver le flag en clair.

Flag attendu (à vérifier après déchiffrement) :  
`FCSC{dca41bafe48c57bf2c9309c485da267d23de04f9}`

---

## 1. Pré-requis

- Linux (Kali/Ubuntu/Debian).
- Client Proxmark3 (Iceman).
- (Optionnel) `mfkey32` / `mfkey32v2` dans le `PATH` pour dériver la clé à partir d’un tuple `(UID, NT, NR, AR, AT)`.

## 2. Installation rapide (outil solver)

```bash
python3 --version
# 3.8+ recommandé

# clonage / copie simple du répertoire
ls -l grand-classic.trace  # la trace fournie
python3 solve_grand_classic.py -h
```

## 3. Usage

Mode auto (si mfkey32 est disponible) :
```bash
python3 solve_grand_classic.py --trace grand-classic.trace -v --grep-flag --dump-tuples tuples.csv
```

Sortie attendue :
- tuples extraits
- tentative mfkey32/mfkey32v2 → clés candidates
- commandes Proxmark3 “offline decrypt” prêtes à copier/coller
- flag à chercher dans `/tmp/decrypted.txt`

## 4. Mode manuel Proxmark3 (offline)

```text
pm3 -o
pm3 --> trace load /chemin/vers/grand-classic.trace
pm3 --> trace list -t 14a          # conf. ISO14443-A, récup UID
pm3 --> trace list -t mf -v        # récup NT/NR/AR/AT
# tuple -> récupérer uid, nt, nr, ar, at en hex
```

Puis côté shell :
```bash
mfkey32v2 <UID> <NT> <NR> <AR> <AT>   # ou mfkey32
# récupère une clé 12 hex (ex: a1b2c3d4e5f6)
```

Déchiffrement/lecture offline :
```text
pm3 -o
pm3 --> trace load /chemin/vers/grand-classic.trace
pm3 --> trace decrypt -k a1b2c3d4e5f6
pm3 --> trace list -t mf -v
pm3 --> trace save /tmp/decrypted.txt
# shell :
strings -n 5 /tmp/decrypted.txt | grep -E 'FCSC\{'
```

## 5. Dépannage

- **Pas de tuples détectés** : utiliser `trace list -t mf -v` pour confirmer la présence d’authentifications (0x60/0x61) dans la trace.
- **mfkey32 introuvable** : compiler depuis le repo Iceman (dossier `tools/mfkey32*`) ou installer depuis packages communautaires.
- **Clé invalide** : tester plusieurs tuples; privilégier ceux où `NT` change (meilleure entropie).

## 6. Sécurité & éthique

Ne déchiffrez que vos propres cartes/échantillons ou dans un cadre autorisé (TP, lab). Le but est pédagogique.

# Write-up — Grand Classic Hotel (MIFARE Classic)

## Résumé
On exploite une trace ISO14443-A / MIFARE Classic capturée par Proxmark3.
L’authentification MIFARE (CRYPTO1) expose, via le quintuple (UID, NT, NR, AR, AT), assez d’information pour dériver la clé 48-bit d’un secteur (attaque mfkey32).
On rejoue ensuite le déchiffrement offline pour extraire le flag ASCII.

**Flag attendu (après déchiffrement)** : `FCSC{dca41bafe48c57bf2c9309c485da267d23de04f9}`

## Étapes
1. Confirmer le type : `trace list -t 14a` puis `trace list -t mf -v`.
2. Extraire les tuples (UID, NT, NR, AR, AT).
3. Dériver la clé via `mfkey32v2 <UID> <NT> <NR> <AR> <AT>` (ou `mfkey32`).
4. Déchiffrer la trace : `trace decrypt -k <KEY>` puis `trace list -t mf -v`.
5. Rechercher `FCSC{...}` dans la sortie claire.

## Preuve
La clé issue du tuple permet le déchiffrement offline de la trace, où le flag apparaît en ASCII.

## Outil fourni
`pm3' (proxmark3) logiciel sans matériel.

## Remarques
- Plusieurs tuples = meilleure robustesse.
- Tentative opportuniste de repérage du flag en clair avec `--grep-flag`.

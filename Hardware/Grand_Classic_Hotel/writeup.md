# Grand Classic Hotel — Write‑Up (aligned with `solve_grand_classic.py`)

> This write‑up is intended for the **FCSC “Grand Classic Hotel”** challenge context (authorized analysis of the provided trace).  
> Do not use these techniques on real access systems without explicit authorization.

## 1. Context (what the trace contains)

The trace corresponds to a **MIFARE Classic** transaction (ISO/IEC 14443‑A at the RF layer) using the proprietary **CRYPTO1** stream cipher for authentication and secured communication. In practice, a lock (reader) and a card perform a mutual authentication that exchanges **nonces** and MAC‑like responses.

### Nonce (in this context)
A *nonce* is a **number used once**: a fresh random (or pseudo‑random) value included in a protocol run to prevent replay.  
For MIFARE Classic authentication, you typically observe a card nonce `Nt` (a.k.a. `NT`) and a reader nonce `Nr` (a.k.a. `NR`), with responses derived from these values and the secret key.

### “Tuple” (in this challenge tooling)
A “tuple” usually denotes a **single authentication transcript** extracted from the trace, e.g.:

- `UID` (card identifier),
- `block` (block being authenticated / accessed),
- `Nt` (card nonce),
- `Nr` (reader nonce),
- `Ar`, `At` (authentication responses).

These tuples are the raw material for key‑recovery tools/attacks (nested/darkside/hardnested, mfkey32, etc.) because they allow reconstructing parts of the keystream and/or exploit weaknesses of CRYPTO1 and/or nonce generation (depending on card type and trace conditions).

## 2. What the provided solver does (and does not do)

The file **`solve_grand_classic.py`** is an *orchestrator* around the **Proxmark3 client**:

- Loads the provided trace into Proxmark3 (`trace load -f ...`)
- Extracts relevant MIFARE Classic information (`trace list -t mf -v`)
- Optionally tries common/default keys via Proxmark’s key dictionary
- Optionally decrypts the trace (only if you **already know a key**)
- Optionally greps the decrypted output for a flag pattern

Important limitation: **this script does not implement the cryptanalytic key recovery itself**.  
It focuses on: *extracting tuples cleanly*, *trying default keys*, and *decrypting/grepping once a key is known*.

## 3. Prerequisites

- Python 3.9+
- A **Proxmark3 client** binary available locally (often `pm3` or `proxmark3`)
- A Proxmark3 build that supports:
  - `trace load`
  - `trace list -t mf -v`
  - `trace decrypt` (for the decryption step)

The solver calls Proxmark3 in “batch” mode via `-c` commands.

## 4. Input trace format (critical)

The solver calls:

```
trace load -f "<TRACE_FILE>"
```

So `--trace` must point to a trace file **loadable by your Proxmark3 client** (often a Proxmark `.trace` capture).

If you only have a `.pcapng`:
- some Proxmark3 builds can load it,
- others cannot (and you will need the original `.trace` capture, or a conversion step).

A quick validation is to run manually:

```
pm3 -c 'trace load -f "your_file"; trace list -t mf -v; exit'
```

If this fails, your issue is not Python: it’s the trace format or Proxmark3 support.

## 5. Correct command line usage

### 5.1 Minimal run (extract UID + auth tuples)
```
python3 solve_grand_classic.py --trace grand-classic.trace -v
```

Notes:
- **There is no positional argument**. Passing `trace.pcapng` alone will fail because `--trace` is required.
- `-v` enables verbose logging (recommended).

### 5.2 Save the Proxmark “trace list” output
```
python3 solve_grand_classic.py --trace grand-classic.trace -v --export-list trace_list.txt
```

### 5.3 Dump parsed authentication tuples to a file
```
python3 solve_grand_classic.py --trace grand-classic.trace -v --dump-tuples tuples.txt
```

### 5.4 Try default keys (fast win if the key is weak/common)
```
python3 solve_grand_classic.py --trace grand-classic.trace -v --try-default-keys
```

### 5.5 Decrypt the trace (only if you already have the key)
Provide a 12‑hex‑char key (6 bytes). Example with the classic default key:

```
python3 solve_grand_classic.py --trace grand-classic.trace -v --key FFFFFFFFFFFF --grep-flag
```

If you want to force a specific sector/key type for decryption:

```
python3 solve_grand_classic.py --trace grand-classic.trace -v --sector 1 --key-type A --key FFFFFFFFFFFF --grep-flag
```

## 6. Why your previous commands failed

### 6.1 Missing `--trace`
Your command:
```
python3 solve_grand_classic.py trace.pcapng -v
```
fails because the solver requires `--trace <path>` (named argument), not a positional file. This is confirmed by the argparse usage output.

### 6.2 Unknown argument `--pm3-out`
The current `solve_grand_classic.py` does **not** define `--pm3-out`.  
To persist outputs, use:

- `--export-list <file>` for the “trace list” output,
- `--dump-tuples <file>` for extracted tuples,
- or shell redirection, e.g. `... | tee solver.log`.

## 7. Typical workflow to reach the flag

1. **Extract tuples**:  
   ```
   python3 solve_grand_classic.py --trace grand-classic.trace -v --dump-tuples tuples.txt
   ```

2. **Recover a key** using an appropriate method/tool for the challenge data
   - Proxmark3 attacks (nested/darkside/hardnested), or
   - external tools (e.g., mfkey32 / mfkey64), depending on what your tuples support.

3. **Decrypt and grep** once you have the key:
   ```
   python3 solve_grand_classic.py --trace grand-classic.trace -v --key <KEYHEX> --grep-flag
   ```

## 8. References (protocol + known weaknesses)

- Proxmark3 trace notes (commands and formats):  
  https://raw.githubusercontent.com/RfidResearchGroup/proxmark3/master/doc/trace_notes.md

- “A Practical Attack on the MIFARE Classic” (Gans, Garcia, van Rossum, Verdult), arXiv 0803.2285:  
  https://arxiv.org/abs/0803.2285  
  https://arxiv.org/pdf/0803.2285.pdf

- “Dismantling MIFARE Classic” (Garcia et al.):  
  https://pdfs.semanticscholar.org/eca8/cc4401e5efc55a60f1d2649ecd69c81f9e81.pdf

- “Card‑Only Attacks on MiFare Classic” (Courtois):  
  https://www.researchgate.net/publication/308390321_Card-Only_Attacks_on_MiFare_Classic

- NXP application note AN10833 (ISO/IEC 14443 & MIFARE details) – mirror:  
  https://www.bdtic.com/download/nxp/AN10833.pdf


---

## 9. Common CLI pitfalls (and the correct commands)

### `--trace` is mandatory (the trace is **not** a positional argument)

These will **fail**:

```bash
python3 solve_grand_classic.py trace.pcapng -v
python3 solve_grand_classic.py trace_mf.txt -v
```

Use **one** of the following correct forms:

```bash
# Minimal
python3 solve_grand_classic.py --trace trace.pcapng -v

# If your proxmark3 client is not in PATH
python3 solve_grand_classic.py --trace trace.pcapng --pm3 ./pm3 -v

# Save the `trace list -t mf` output to a file (for later/manual inspection)
python3 solve_grand_classic.py --trace trace.pcapng --export-list trace_mf.txt -v

# Extract authentication tuples (UID, Nt, Nr, Ar, At) for mfkey32 / nested tooling
python3 solve_grand_classic.py --trace trace.pcapng --dump-tuples tuples_mfkey32.txt -v
```

Notes:
- `--pm3-out` is **not** an option in the current solver. Use `--export-list` instead.
- `--mfkey32` is also **not** integrated in the current solver: it **extracts tuples**, but you must run your key-recovery tool yourself (mfkey32 / nested / hardnested).

### `UID (from SELECT/ANTICOLL): 46435343` is **not a key**

- This line is the card **UID** (identifier) observed during ISO/IEC 14443-A anticollision/SELECT.
- A MIFARE Classic sector key is **6 bytes** (12 hex chars), e.g. `FFFFFFFFFFFF` or `A0A1A2A3A4A5`.
- Here `46435343` is **4 bytes** and decodes to ASCII `FCSC`, which is consistent with a “themed” UID and not with a MIFARE key.

If you later see an actual key in logs/output, it will look like **12 hex digits** (or 6 bytes), and usually be labeled **Key A** or **Key B** for a given sector.

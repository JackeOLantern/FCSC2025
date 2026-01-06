# Grand Classic Hotel — solver (MIFARE Classic / CRYPTO1)

This repository contains a Python helper script to **extract Crypto1 authentication tuples** from a Proxmark3 trace and, when possible, **recover MIFARE Classic sector keys** using `mfkey32v2`.

> Important: the solver **does not accept a positional trace file argument**. You must pass `--trace <file>`.

---

## 1) Prerequisites

### Required
- Python 3

### Recommended
- **Proxmark3 client** (`pm3`) from the Iceman fork (or an equivalent build), to:
  - load the capture (`.pcapng`) and export a MIFARE-filtered trace file (`.trace`)
  - decrypt the trace once a key is recovered

### Optional (for automatic key recovery)
- `mfkey32v2` (or a compatible `mfkey32`) available in your PATH, or provided via `--mfkey`.

---

## 2) Prepare the trace file

The solver expects a **Proxmark3 trace text file** (exported with `trace list ... -f`), typically named `grand-classic.trace`.

If you currently have a Wireshark capture (`trace.pcapng`), generate the `.trace` file with `pm3`:

```text
pm3 -o
trace load trace.pcapng
trace list -1 -t mf -f grand-classic.trace
exit
```

You should now have `grand-classic.trace` in the current directory.

---

## 3) Run the solver

### Basic usage (verbose)
```bash
python3 solve_grand_classic.py --trace grand-classic.trace -v
```

### With tuple export + grep for the flag
```bash
python3 solve_grand_classic.py --trace grand-classic.trace -v   --dump-tuples tuples.csv   --grep-flag
```

### If `mfkey32v2` is not in PATH
```bash
python3 solve_grand_classic.py --trace grand-classic.trace -v   --mfkey ./mfkey32v2
```

### If you only want to extract tuples (no key recovery attempt)
```bash
python3 solve_grand_classic.py --trace grand-classic.trace -v --no-mfkey --dump-tuples tuples.csv
```

---

## 4) CLI options (current solver)

From `python3 solve_grand_classic.py -h`:

- `--trace PATH` (required): Proxmark3-exported trace file (text).
- `--mfkey PATH`: Path to `mfkey32v2`/`mfkey32` binary.
- `--no-mfkey`: Do not call `mfkey32` automatically (tuple extraction only).
- `--dump-tuples PATH`: Write extracted tuples to a CSV file.
- `--grep-flag`: After printing the suggested `pm3` commands, also print a shell one-liner to grep `FCSC{...}` in the decrypted output.
- `-v`, `--verbose`: Print additional diagnostics (UID detection, tuple count, per-tuple details, mfkey32 execution details).

### What “verbose” shows (`-v`)
With `-v`, the solver prints:
- the UID discovered in the trace (from `SELECT/ANTICOLL`)
- how many authentication tuples were extracted
- each tuple (UID, `NT`, `NR`, `AR`, `AT`) as it is processed
- the exact `mfkey32v2` command that is executed (and its stdout/stderr when relevant)

---

## 5) Outputs and next steps

### Script output
The solver prints:
- a summary of extracted tuples
- recovered key(s) if `mfkey32v2` succeeds
- **ready-to-paste Proxmark3 commands** to decrypt the trace offline, e.g.:

```text
pm3 -o
trace load grand-classic.trace
trace decrypt -k <KEY_HEX>
trace save -f /tmp/decrypted.txt
trace list -1
exit
```

### Files written
- `--dump-tuples tuples.csv`: extracted tuples as CSV
- When using the printed `pm3` commands, the decrypted trace is saved as: `/tmp/decrypted.txt`

---

## 6) Troubleshooting

### “the following arguments are required: --trace”
You likely ran:
```bash
python3 solve_grand_classic.py trace.pcapng -v
```
This solver requires:
```bash
python3 solve_grand_classic.py --trace grand-classic.trace -v
```
and the input must be a **Proxmark3-exported `.trace`**, not the raw `.pcapng`.

### No key recovered
This is common if:
- the capture is noisy / incomplete
- the tuple is not clean enough for `mfkey32v2` (missing bytes, corrupted frames)

In that case:
1. export tuples (`--dump-tuples`)
2. pick the cleanest tuple and retry manually:
   ```bash
   mfkey32v2 <uid> <nt> <nr> <ar> <at>
   ```

---

## 7) Background (short)

A “tuple” in this context is the set of values exchanged during a MIFARE Classic authentication:
`(UID, NT, NR, AR, AT)`.
These values are tied to the **CRYPTO1 stream cipher** and are used by tools like `mfkey32v2` to recover the secret key when the capture provides a usable authentication transcript.

---

## 8) References (for deeper reading)

- NXP documentation: **MIFARE Classic** (datasheets and application notes)
- Karsten Nohl, Henryk Plötz: early public analyses of **CRYPTO1**
- Garcia et al.: **“Dismantling MIFARE Classic”** (widely cited academic paper on the practical break)

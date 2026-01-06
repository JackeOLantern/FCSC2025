#!/usr/bin/env python3
"""
Grand Classic Hotel solver (offline).

Why your previous runs failed:
- Your pm3 build accepts only ONE "-c <command>" (the last one wins).
  In v8, that meant ONLY "quit" ran, so nothing was loaded/listed and UID/blocks were None.

Fix:
- Use ONE "-c" and chain pm3 subcommands with ";" so they run in a single pm3 session
  and keep the tracebuffer.

Examples:
  python3 solve_grand_classic.py --trace grand-classic.trace --grep-flag -v
  python3 solve_grand_classic.py --trace grand-classic.trace --key FFFFFFFFFFFF --grep-flag -v
  python3 solve_grand_classic.py --trace grand-classic.trace --export-list pm3_out.txt --dump-tuples tuples.csv -v

Notes:
- We do NOT pass "trace list ... -v" because your pm3 reports it invalid.
- "--dict mfc_default_keys" support varies by pm3 build; enable via --try-default-keys if it works.

This solver filters the relevant data from the blocks then it gets a flag.
Author : JG
"""

import argparse
import csv
import re
import shutil
import subprocess
import sys
from pathlib import Path


def which_pm3(user_path: str) -> str | None:
    if user_path and shutil.which(user_path):
        return user_path
    for cand in ("pm3", "proxmark3"):
        if shutil.which(cand):
            return cand
    return None


def run_pm3_chained(pm3: str, cmd: str, verbose: bool, timeout: int) -> str:
    args = [pm3, "-c", cmd]
    if verbose:
        print("[pm3] run:", " ".join(args), file=sys.stderr)
    try:
        p = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            check=False,
        )
        if verbose:
            print(p.stdout)
        return p.stdout
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or "")
        out += "\n[!] pm3 execution timed out. Increase --pm3-timeout.\n"
        if verbose:
            print(out)
        return out


def parse_uid_from_select(lines: list[str]) -> str | None:
    # Preferred: SELECT_UID row, grab bytes after 93 70
    for ln in lines:
        if "SELECT_UID" in ln:
            m = re.search(r"Rdr\s*\|([^|]+)\|", ln)
            if not m:
                continue
            hexes = [h.upper() for h in re.findall(r"[0-9A-Fa-f]{2}", m.group(1))]
            try:
                i93 = hexes.index("93")
                if i93 + 5 < len(hexes) and hexes[i93 + 1] == "70":
                    uid = hexes[i93 + 2 : i93 + 6]
                    if len(uid) == 4:
                        return "".join(uid)
            except ValueError:
                pass

    # Fallback: ANTICOLL Tag response (first 4 bytes)
    for ln in lines:
        if "ANTICOLL" in ln and "Tag |" in ln:
            m = re.search(r"Tag\s*\|([^|]+)\|", ln)
            if not m:
                continue
            hexes = [h.upper() for h in re.findall(r"[0-9A-Fa-f]{2}", m.group(1))]
            if len(hexes) >= 4:
                return "".join(hexes[:4])

    return None


def parse_auth_tuples(lines: list[str], uid_hex: str | None) -> list[dict]:
    tuples = []
    current_block = None
    pending = {"nt": None, "nr": None, "ar": None, "at": None}

    for ln in lines:
        m_auth = re.search(r"AUTH-[AB]\((\d+)\)", ln)
        if m_auth:
            if any(pending.values()):
                tuples.append(
                    {
                        "uid": uid_hex,
                        "block": current_block,
                        "nt": pending["nt"],
                        "nr": pending["nr"],
                        "ar": pending["ar"],
                        "at": pending["at"],
                    }
                )
            current_block = int(m_auth.group(1))
            pending = {"nt": None, "nr": None, "ar": None, "at": None}
            continue

        if "AUTH: nt" in ln:
            m = re.search(r"AUTH:\s*nt.*?([0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2}){3})", ln)
            if m:
                pending["nt"] = "".join(re.findall(r"[0-9A-Fa-f]{2}", m.group(1))).upper()
            continue

        if "AUTH: nr ar" in ln:
            m = re.search(r"AUTH:\s*nr\s+ar.*?([0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2}){7})", ln)
            if m:
                eight = [h.upper() for h in re.findall(r"[0-9A-Fa-f]{2}", m.group(1))]
                if len(eight) == 8:
                    pending["nr"] = "".join(eight[0:4])
                    pending["ar"] = "".join(eight[4:8])
            continue

        if "AUTH: at" in ln:
            m = re.search(r"AUTH:\s*at.*?([0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2}){3})", ln)
            if m:
                pending["at"] = "".join(re.findall(r"[0-9A-Fa-f]{2}", m.group(1))).upper()
                tuples.append(
                    {
                        "uid": uid_hex,
                        "block": current_block,
                        "nt": pending["nt"],
                        "nr": pending["nr"],
                        "ar": pending["ar"],
                        "at": pending["at"],
                    }
                )
                pending = {"nt": None, "nr": None, "ar": None, "at": None}
                current_block = None

    return tuples


def parse_read_blocks(lines: list[str], target_blocks=(4, 5, 6)) -> dict[int, list[str]]:
    """
    Look for READBLOCK(n) and then read the plaintext line that pm3 prints as:
        | * | 46 43 53 ...
    """
    result: dict[int, list[str]] = {}
    for i, ln in enumerate(lines):
        m = re.search(r"READBLOCK\((\d+)\)", ln)
        if not m:
            continue
        blk = int(m.group(1))
        if blk not in target_blocks:
            continue

        for j in range(i + 1, min(i + 20, len(lines))):
            nxt = lines[j]

            m2 = re.search(r"\*\s*\|\s*([0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2}){15,})\s*\|", nxt)
            if m2:
                hexes = re.findall(r"[0-9A-Fa-f]{2}", m2.group(1))
                if len(hexes) >= 16:
                    result[blk] = [h.upper() for h in hexes[:16]]
                    break

            # Some builds show plaintext in the Tag row after decrypt
            if "Tag |" in nxt and " ok " in (" " + nxt + " "):
                m3 = re.search(r"Tag\s*\|\s*([0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2}){15,})", nxt)
                if m3:
                    hexes = re.findall(r"[0-9A-Fa-f]{2}", m3.group(1))
                    if len(hexes) >= 16:
                        result[blk] = [h.upper() for h in hexes[:16]]
                        break
    return result


def hex_to_ascii(hex_list: list[str]) -> str:
    try:
        bs = bytes(int(h, 16) for h in hex_list)
        return bs.decode("ascii", errors="ignore")
    except Exception:
        return ""


def main() -> None:
    ap = argparse.ArgumentParser(description="Grand Classic Hotel solver (offline, chains pm3 commands in one -c).")
    ap.add_argument("--trace", required=True, help="Path to grand-classic.trace")
    ap.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    ap.add_argument("--pm3", default="pm3", help="pm3 binary name/path (default: pm3; fallback: proxmark3)")
    ap.add_argument("--pm3-timeout", type=int, default=45, help="Timeout (seconds) for the whole pm3 run (default: 45)")
    ap.add_argument("--key", default=None, help="12-hex MIFARE key for 'trace decrypt -k' (e.g., FFFFFFFFFFFF).")
    ap.add_argument("--no-decrypt", action="store_true", help="Skip decrypt step")
    ap.add_argument("--try-default-keys", action="store_true", help="Extra pass: trace list -1 -t mf --dict mfc_default_keys (if supported).")
    ap.add_argument("--grep-flag", action="store_true", help="Reconstruct flag from READBLOCK(4/5/6) plaintext")
    ap.add_argument("--dump-tuples", default=None, help="CSV path for AUTH tuples (uid,block,nt,nr,ar,at)")
    ap.add_argument("--export-list", default=None, help="Write combined pm3 output to this file")
    args = ap.parse_args()

    trace = Path(args.trace).expanduser().resolve()
    if not trace.exists():
        print(f"[!] Trace file not found: {trace}", file=sys.stderr)
        sys.exit(2)

    pm3 = which_pm3(args.pm3)
    if not pm3:
        print("[!] pm3 client not found (tried: pm3, proxmark3). Install it or pass --pm3 PATH.", file=sys.stderr)
        sys.exit(3)

    parts: list[str] = [
        f'trace load -f "{trace}"',
        "trace list -1 -t 14a",
        "trace list -1 -t mf",
    ]

    if args.try_default_keys:
        parts.append("trace list -1 -t mf --dict mfc_default_keys")

    if not args.no_decrypt and args.key and args.key.lower() != "none":
        if not re.fullmatch(r"[0-9a-fA-F]{12}", args.key):
            print("[!] --key must be 12 hex (example: FFFFFFFFFFFF)", file=sys.stderr)
            sys.exit(4)
        parts.append(f"trace decrypt -k {args.key}")
        parts.append("trace list -1 -t mf")

    # Terminate (some builds accept exit, some quit)
    parts.append("exit")
    cmd = "; ".join(parts)

    out = run_pm3_chained(pm3, cmd, verbose=args.verbose, timeout=args.pm3_timeout)

    if args.export_list:
        Path(args.export_list).write_text(out, encoding="utf-8")

    lines = out.splitlines()

    uid_hex = parse_uid_from_select(lines)
    print(f"[*] UID (from SELECT/ANTICOLL): {uid_hex}", file=sys.stderr)

    if args.dump_tuples:
        tuples = parse_auth_tuples(lines, uid_hex)
        with open(args.dump_tuples, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["uid", "block", "nt", "nr", "ar", "at"])
            for t in tuples:
                w.writerow([t.get("uid", ""), t.get("block", ""), t.get("nt", ""), t.get("nr", ""), t.get("ar", ""), t.get("at", "")])
        print(f"[*] Wrote {len(tuples)} AUTH tuples to {args.dump_tuples}", file=sys.stderr)

    if args.grep_flag:
        blocks = parse_read_blocks(lines, target_blocks=(4, 5, 6))
        if {4, 5, 6}.issubset(blocks.keys()):
            s = (hex_to_ascii(blocks[4]) + hex_to_ascii(blocks[5]) + hex_to_ascii(blocks[6]))
            s = s.replace("\x00", "")
            m = re.search(r"(FCSC\{[0-9a-fA-F]+\})", s)
            print(m.group(1) if m else s)
        else:
            got = sorted(blocks.keys())
            print(f"[!] Could not extract blocks 4/5/6 (got {got}).", file=sys.stderr)
            print("    Your pm3 must print decrypted plaintext lines (the lines starting with '* | ...').", file=sys.stderr)
            print("    If it does not, force decrypt with:", file=sys.stderr)
            print("      python3 solve_grand_classic_v9.py --trace grand-classic.trace --key FFFFFFFFFFFF --grep-flag -v", file=sys.stderr)
            print("    Or run pm3 manually (single -c):", file=sys.stderr)
            print('      pm3 -c \'trace load -f "grand-classic.trace"; trace decrypt -k FFFFFFFFFFFF; trace list -1 -t mf; exit\'', file=sys.stderr)
            sys.exit(5)


if __name__ == "__main__":
    main()

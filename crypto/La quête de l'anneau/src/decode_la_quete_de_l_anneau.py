import json
from math import gcd
from functools import reduce

def recover_flag_from_file(filename):
    with open(filename, "r") as f:
        j = json.load(f)

    data = j["data"]
    C = j["C"]

    # Étape 1 : calculer s
    def get_relation(entry):
        return entry["m"] * entry["iv"] - entry["c"]

    relations = [get_relation(entry) for entry in data]
    s = reduce(gcd, relations)

    print(f"[+] Clé retrouvée :\ns = {s}\n")

    # Étape 2 : déchiffrer
    bs = len(C[0]["c"].to_bytes((C[0]["c"].bit_length() + 7) // 8, "big"))

    flag = b""
    for d in C:
        iv = d["iv"]
        c = d["c"]
        m = c * pow(iv, -1, s) % s
        flag += m.to_bytes(bs, "big")

    try:
        print(f"[+] Flag : {flag.decode()}")
    except UnicodeDecodeError:
        print(f"[+] Flag (raw bytes) : {flag}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 recover_flag.py <fichier_output.json>")
    else:
        recover_flag_from_file(sys.argv[1])

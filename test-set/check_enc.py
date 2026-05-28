"""
check_enc.py - Verify .enc files survived 7-Zip + GitHub transfer unchanged.

Run this on BOTH laptops (before sending, and after extracting) and compare
the SHA-256 lines. If the SHA-256 is identical on both machines, the file is
byte-for-byte intact and any unlock failure is a PASSWORD problem, not transfer.
If the SHA-256 differs, the file was corrupted in transit.

Usage:
    python check_enc.py                          # checks the two default files
    python check_enc.py file1.enc file2.enc      # checks the files you name
    python check_enc.py *.enc                     # checks every .enc here

Optional: add --unlock to also test that a password actually decrypts the file.
    python check_enc.py --unlock
"""
import sys
import hashlib
from pathlib import Path

DEFAULT_FILES = ["dr_plant_train.csv.enc", "dr_plant_test.csv.enc"]


def sha256_of(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def report(path):
    p = Path(path)
    if not p.exists():
        print(f"  [MISSING] {path}  <-- file not found here")
        return
    data = p.read_bytes()
    size = len(data)
    digest = sha256_of(p)
    head = data[:16].hex()
    tail = data[-16:].hex()
    print(f"  File   : {p.name}")
    print(f"  Size   : {size} bytes")
    print(f"  SHA-256: {digest}")
    print(f"  First16: {head}")
    print(f"  Last16 : {tail}")
    # sanity: minimum size = salt(16)+nonce(16)+mac(32) = 64 bytes
    if size < 64:
        print("  [WARN] Smaller than 64 bytes - this is NOT a valid .enc file "
              "(likely truncated or wrong file).")
    print()


def try_unlock(files):
    try:
        from scoring_phase1 import load_encrypted_table
    except Exception as e:
        print(f"[unlock] Could not import scoring_phase1.py ({e}). "
              f"Run this in the same folder as scoring_phase1.py.")
        return
    import getpass
    pw = getpass.getpass("[unlock] Enter the .enc password to test decryption: ")
    for f in files:
        if not Path(f).exists():
            print(f"  [MISSING] {f}")
            continue
        try:
            df = load_encrypted_table(f, pw)
            print(f"  [OK]      {f}  -> decrypted, {df.shape[0]} rows x {df.shape[1]} cols")
        except Exception as e:
            print(f"  [FAIL]    {f}  -> {e}")
    print()


def main():
    args = [a for a in sys.argv[1:] if a != "--unlock"]
    do_unlock = "--unlock" in sys.argv
    files = args or DEFAULT_FILES

    print("=" * 60)
    print("BYTE CHECK FOR .enc FILES")
    print("Compare the SHA-256 lines between the two laptops.")
    print("=" * 60)
    print()
    for f in files:
        report(f)

    if do_unlock:
        print("-" * 60)
        print("DECRYPTION TEST")
        print("-" * 60)
        try_unlock(files)

    print("How to read this:")
    print("  - SHA-256 SAME on both laptops  -> file is intact; if unlock still")
    print("    fails it is a password issue (zip pw vs .enc pw mix-up).")
    print("  - SHA-256 DIFFERENT              -> file got corrupted by GitHub or")
    print("    extraction; re-send it (keep it inside the zip / use a Release).")


if __name__ == "__main__":
    main()
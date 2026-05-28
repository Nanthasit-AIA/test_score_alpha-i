"""
Lock ground-truth CSVs with a password.

Usage:
    python encrypt_gt.py                       # locks dr_plant_train.csv & dr_plant_test.csv
    python encrypt_gt.py file1.csv file2.csv   # locks the given files

Each <name>.csv becomes <name>.csv.enc. After verifying the .enc files work
with scoring_phase1.py, DELETE the plaintext CSVs so they can't be opened.
"""
import sys
import getpass
from pathlib import Path

from scoring_phase1 import encrypt_file, load_encrypted_table


def main():
    targets = sys.argv[1:] or [r"dr_plant_train.csv", r"dr_plant_test.csv"]

    missing = [t for t in targets if not Path(t).exists()]
    if missing:
        print("These files were not found:", ", ".join(missing))
        sys.exit(1)

    pw = getpass.getpass("Set a password to lock the ground-truth files: ")
    pw2 = getpass.getpass("Confirm password: ")
    if pw != pw2:
        print("Passwords do not match. Nothing was locked.")
        sys.exit(1)
    if not pw:
        print("Empty password rejected.")
        sys.exit(1)

    for t in targets:
        out = str(t) + ".enc"
        encrypt_file(t, out, pw)
        # Verify it can be reopened with the same password before trusting it.
        load_encrypted_table(out, pw)
        print(f"Locked {t} -> {out}")

    print("\nDone. The .enc files are verified readable with your password.")
    print("You can now delete the plaintext CSVs:")
    for t in targets:
        print(f"  rm {t}")


if __name__ == "__main__":
    main()

import io
import os
import hmac
import hashlib
import getpass
import pandas as pd
from pathlib import Path
from datetime import datetime
import time

# ============================================================
# NOTE: CONFIG
# ============================================================
TRAIN_PRED_CSV = r"c:\Users\idtcu\Alpha-I\test\dr_plant_train.csv"
TEST_PRED_CSV = r"c:\Users\idtcu\Alpha-I\test\dr_plant_test.csv"



# ============================================================
# BASIC FUNCTIONS
# ============================================================
TRAIN_GT_ENC = "dr_plant_train.csv.enc"
TEST_GT_ENC = "dr_plant_test.csv.enc"
KEY_COL = "timestamp"
MAX_SCORE = 25

SALT_SIZE = 16
NONCE_SIZE = 16
MAC_SIZE = 32
PBKDF2_ITERATIONS = 200_000

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

def green_pass(text):
    return f"{GREEN}PASSED{RESET} - {text}"

def red_fail(text):
    return f"{RED}FAILED{RESET} - {text}"

def yellow_warn(text):
    return f"{YELLOW}WARNING{RESET} - {text}"

def is_missing(value):
    if pd.isna(value):
        return True

    value_str = str(value).strip().lower()
    return value_str in ["", "nan", "none", "null"]

def cells_equal(a, b, numeric_tol=1e-9, case_sensitive=False):
    if is_missing(a) and is_missing(b):
        return True

    if is_missing(a) or is_missing(b):
        return False

    try:
        return abs(float(a) - float(b)) <= numeric_tol
    except Exception:
        pass

    a_text = str(a).strip()
    b_text = str(b).strip()

    if not case_sensitive:
        a_text = a_text.lower()
        b_text = b_text.lower()

    return a_text == b_text

def load_table(file_path, sheet_name=None):
    file_path = Path(file_path)

    if file_path.suffix.lower() == ".csv":
        return pd.read_csv(file_path)

    if file_path.suffix.lower() in [".xlsx", ".xls"]:
        return pd.read_excel(file_path, sheet_name=sheet_name)

    raise ValueError("Only .csv, .xlsx, and .xls files are supported.")

# ============================================================
# GROUND-TRUTH 
# ============================================================
def _derive_keys(password, salt):
    master = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=64
    )
    return master[:32], master[32:]

def _keystream(enc_key, nonce, length):
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(hmac.new(enc_key, nonce + counter.to_bytes(8, "big"),
                            hashlib.sha256).digest())
        counter += 1
    return bytes(out[:length])

def _xor(data, keystream):
    if not data:
        return b""
    return (int.from_bytes(data, "big") ^ int.from_bytes(keystream, "big")).to_bytes(
        len(data), "big"
    )

def encrypt_file(plaintext_path, encrypted_path, password):
    data = Path(plaintext_path).read_bytes()
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    enc_key, mac_key = _derive_keys(password, salt)
    ciphertext = _xor(data, _keystream(enc_key, nonce, len(data)))
    tag = hmac.new(mac_key, salt + nonce + ciphertext, hashlib.sha256).digest()
    Path(encrypted_path).write_bytes(salt + nonce + tag + ciphertext)
    return encrypted_path

def decrypt_bytes(encrypted_path, password):
    blob = Path(encrypted_path).read_bytes()
    if len(blob) < SALT_SIZE + NONCE_SIZE + MAC_SIZE:
        raise ValueError("Corrupted encrypted ground-truth file (too short).")
    salt = blob[:SALT_SIZE]
    nonce = blob[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    tag = blob[SALT_SIZE + NONCE_SIZE:SALT_SIZE + NONCE_SIZE + MAC_SIZE]
    ciphertext = blob[SALT_SIZE + NONCE_SIZE + MAC_SIZE:]
    enc_key, mac_key = _derive_keys(password, salt)
    expected = hmac.new(mac_key, salt + nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("Wrong password or corrupted encrypted ground-truth file.")
    return _xor(ciphertext, _keystream(enc_key, nonce, len(ciphertext)))

def load_encrypted_table(encrypted_path, password):
    raw = decrypt_bytes(encrypted_path, password)
    return pd.read_csv(io.BytesIO(raw))

# ============================================================
# COMPARISON FUNCTION
# ============================================================
def compare_tables(
    ground_truth_df,
    prediction_df,
    key_col=None,
    exclude_cols=None,
    max_score=25,
    numeric_tol=1e-9,
):
    gt = ground_truth_df.copy()
    pred = prediction_df.copy()

    gt.columns = [str(c).strip() for c in gt.columns]
    pred.columns = [str(c).strip() for c in pred.columns]

    exclude_cols = exclude_cols or []

    if key_col is not None:
        if key_col not in gt.columns:
            raise ValueError(f"key_col '{key_col}' not found in ground truth table.")

        if key_col not in pred.columns:
            raise ValueError(f"key_col '{key_col}' not found in prediction table.")

        if gt[key_col].duplicated().any():
            raise ValueError(f"Duplicate key values found in ground truth column '{key_col}'.")

        if pred[key_col].duplicated().any():
            raise ValueError(f"Duplicate key values found in prediction column '{key_col}'.")

        gt = gt.set_index(key_col, drop=False)
        pred = pred.set_index(key_col, drop=False)

        row_keys = sorted(set(gt.index).union(set(pred.index)))
        ignore_cols = set([key_col] + exclude_cols)

    else:
        gt["_row_no"] = range(1, len(gt) + 1)
        pred["_row_no"] = range(1, len(pred) + 1)

        gt = gt.set_index("_row_no")
        pred = pred.set_index("_row_no")

        row_keys = sorted(set(gt.index).union(set(pred.index)))
        ignore_cols = set(["_row_no"] + exclude_cols)

    compare_cols = sorted((set(gt.columns).union(set(pred.columns))) - ignore_cols)

    details = []

    for row_key in row_keys:
        for col in compare_cols:
            gt_row_exists = row_key in gt.index
            pred_row_exists = row_key in pred.index
            gt_col_exists = col in gt.columns
            pred_col_exists = col in pred.columns

            gt_exists = gt_row_exists and gt_col_exists
            pred_exists = pred_row_exists and pred_col_exists

            gt_value = gt.loc[row_key, col] if gt_exists else None
            pred_value = pred.loc[row_key, col] if pred_exists else None

            is_match = False

            if gt_exists and pred_exists:
                is_match = cells_equal(gt_value, pred_value, numeric_tol=numeric_tol)

            details.append({
                "row_key": row_key,
                "column": col,
                "ground_truth_value": gt_value,
                "prediction_value": pred_value,
                "match": is_match,
                "gt_exists": gt_exists,
                "prediction_exists": pred_exists,
            })

    detail_df = pd.DataFrame(details)

    total_cells = len(detail_df)
    matched_cells = int(detail_df["match"].sum())

    accuracy = matched_cells / total_cells if total_cells > 0 else 0
    score = accuracy * max_score

    summary = {
        "matched_cells": matched_cells,
        "total_cells": total_cells,
        "accuracy": round(accuracy, 4),
        "score_out_of_25": round(score, 4),
        "max_score": max_score,
    }

    row_score_df = (
        detail_df
        .groupby("row_key")
        .agg(
            matched_cells=("match", "sum"),
            total_cells=("match", "count")
        )
        .reset_index()
    )

    row_score_df["row_score_out_of_25"] = (
        row_score_df["matched_cells"] / row_score_df["total_cells"] * max_score
    ).round(4)

    return summary, detail_df, row_score_df

# ============================================================
# COMPARE ONE PAIR  
# ============================================================
def compare_pair(
    pair_name,
    ground_truth_df,
    prediction_df,
    ground_truth_label,
    prediction_label,
    key_col=None,
    max_score=25,
):
    summary, detail_df, row_score_df = compare_tables(
        ground_truth_df=ground_truth_df,
        prediction_df=prediction_df,
        key_col=key_col,
        max_score=max_score,
    )

    summary["pair_name"] = pair_name
    summary["ground_truth_file"] = str(ground_truth_label)
    summary["prediction_file"] = str(prediction_label)

    return summary, detail_df, row_score_df

# ============================================================
# MAIN RUN
# ============================================================
def main():
    start_time = time.perf_counter()
    password = getpass.getpass("Enter password to unlock ground-truth files: ")

    gt_train_df = load_encrypted_table(TRAIN_GT_ENC, password)
    gt_test_df = load_encrypted_table(TEST_GT_ENC, password)

    train_summary, _, _ = compare_pair(
        pair_name="train",
        ground_truth_df=gt_train_df,
        prediction_df=load_table(TRAIN_PRED_CSV),
        ground_truth_label=TRAIN_GT_ENC,
        prediction_label=TRAIN_PRED_CSV,
        key_col=KEY_COL,
        max_score=MAX_SCORE,
    )

    test_summary, _, _ = compare_pair(
        pair_name="test",
        ground_truth_df=gt_test_df,
        prediction_df=load_table(TEST_PRED_CSV),
        ground_truth_label=TEST_GT_ENC,
        prediction_label=TEST_PRED_CSV,
        key_col=KEY_COL,
        max_score=MAX_SCORE,
    )

    runtime_seconds = time.perf_counter() - start_time
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("\n********** Final Summary Score **********")
    print(f"Timestamp:      {now}")
    print(f"Runtime:        {runtime_seconds:.4f} seconds")

    print("\n========== TRAIN RESULT ==========")
    print(f"Matched Cells:      {train_summary['matched_cells']/6}")
    print(f"Total Cells:        {train_summary['total_cells']/6}")
    print(f"Accuracy:           {train_summary['accuracy']:.4f}")
    print(f"Score out of 25:    {train_summary['score_out_of_25']}")
    print(f"Max Score:          {train_summary['max_score']}")

    print("\n========== TEST RESULT ==========")
    print(f"Matched Cells:      {test_summary['matched_cells']/6}")
    print(f"Total Cells:        {test_summary['total_cells']/6}")
    print(f"Accuracy:           {test_summary['accuracy']:.4f}")
    print(f"Score out of 25:    {test_summary['score_out_of_25']}")
    print(f"Max Score:          {test_summary['max_score']}")

    print("\n*****************************************")
    print(f"PHASE1:Total Score:        {(train_summary['score_out_of_25'] + test_summary['score_out_of_25']) / 2}")

if __name__ == "__main__":
    main()
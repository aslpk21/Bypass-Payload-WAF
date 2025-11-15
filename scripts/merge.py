import pandas as pd
import chardet
import sys

def detect_encoding(file_path):
    """Detect encoding reliably using chardet."""
    with open(file_path, "rb") as f:
        raw = f.read()
        result = chardet.detect(raw)
        return result["encoding"]


def read_csv_safe(path):
    """Read CSV without corrupting encoding."""
    encoding = detect_encoding(path)
    print(f"[INFO] File: {path} - Detected encoding = {encoding}")

    try:
        df = pd.read_csv(path, encoding=encoding, dtype=str, keep_default_na=False)
    except Exception as e:
        print(f"[ERROR] Failed to parse CSV normally: {e}")
        print("[INFO] Falling back to safe-load...")

        with open(path, "rb") as f:
            content = f.read().decode(encoding, errors="replace")

        lines = content.splitlines()
        rows = [line.split(",") for line in lines]
        max_len = max(len(r) for r in rows)
        padded = [r + [""] * (max_len - len(r)) for r in rows]
        df = pd.DataFrame(padded)

    # 🔥 Remove Unnamed columns
    df = df.loc[:, ~df.columns.str.contains("^Unnamed")]

    return df


def merge_csvs(output_path, *csv_files):
    dfs = []

    for file in csv_files:
        df = read_csv_safe(file)
        print(f"[INFO] Loaded {file}: {df.shape[0]} rows, {df.shape[1]} cols")
        dfs.append(df)

    # align columns across all files
    all_columns = sorted(set().union(*[df.columns for df in dfs]))
    dfs = [df.reindex(columns=all_columns, fill_value="") for df in dfs]

    final_df = pd.concat(dfs, ignore_index=True)

    # Save output as UTF-16 (safe for all characters)
    final_df.to_csv(output_path, index=False, encoding="utf-16")

    print(f"[DONE] Saved merged file to: {output_path}")
    print(f"Total rows: {final_df.shape[0]}")


if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Usage: python merge_csv_safe.py out.csv file1.csv file2.csv file3.csv")
        sys.exit(1)

    out = sys.argv[1]
    files = sys.argv[2:]
    merge_csvs(out, *files)

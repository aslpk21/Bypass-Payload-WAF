import numpy as np
import pandas as pd

data_path = "./dataset_raw/SQLi/sqli_merged.csv"
for enc in ['utf-8', 'utf-8-sig', 'utf-16', 'utf-16le', 'utf-16be', 'latin1', 'cp1252']:
    try:
        df = pd.read_csv(data_path, encoding=enc)
        print(f"[INFO] Đọc file thành công với encoding = {enc}")
        print(df)
        break
    except Exception as e:
        print(f"[WARN] Thử {enc} lỗi:", str(e)[:80])
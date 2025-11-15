import numpy as np
import pandas as pd

data_path = "./dataset_raw/SQLi/sqli_mergedv3.csv"       # CSV chứa cột Sentence, Label

# === LOAD DATA ===
df = pd.read_csv(data_path, encoding='utf-8')
print(df.head())

sentences = df["Sentence"].astype(str).tolist()
labels = df["Label"].astype(int).values
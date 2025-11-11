#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
README — UniEmbed ML Training Script (XSS & SQLi)

Description:
  Train ML models (MLP, RandomForest, SVM) and VotingClassifiers using UniEmbed features
  (Word2Vec + FastText + USE) to detect XSS and SQL injection payloads.

Input:
  CSV file with two columns:
    - Sentence (string payload)
    - Label (0 for benign, 1 for malicious)

Output:
  - Trained models saved to models/:
      * scaler.pkl
      * mlp.pkl
      * rf.pkl
      * svm.pkl
      * voting_hard.pkl
      * voting_soft.pkl
  - Metrics report CSV saved to reports/metrics_report.csv
  - Confusion matrix images saved to reports/confusion_*.png
  - ROC curve images saved to reports/roc_*.png
  - Train time per model printed in console with a metrics table

Dependencies (install via pip):
  - pandas
  - numpy
  - scikit-learn
  - gensim
  - fasttext (a.k.a. fasttext-wheel for some platforms)
  - tensorflow
  - tensorflow_hub
  - matplotlib
  - seaborn
  - joblib

Pre-trained embeddings (download/load):
  - Universal Sentence Encoder (USE):
      https://tfhub.dev/google/universal-sentence-encoder/4
      (loaded directly via tensorflow_hub)
  - Word2Vec (GoogleNews 300-d vectors, ~1.5GB):
      https://code.google.com/archive/p/word2vec/
      Direct file (GoogleNews-vectors-negative300.bin.gz) often mirrored;
      Gensim can load with KeyedVectors.
  - FastText (English, 300-d):
      https://dl.fbaipublicfiles.com/fasttext/vectors-wiki/wiki.en.bin
      or Common Crawl:
      https://dl.fbaipublicfiles.com/fasttext/vectors-crawl/cc.en.300.bin.gz

How to run:
  python uniembed_train.py --input data.csv --w2v_path /path/to/GoogleNews-vectors-negative300.bin.gz \
                           --ft_path /path/to/wiki.en.bin \
                           --test_size 0.2 --random_state 42

Notes:
  - If your environment lacks GPU, USE / TensorFlow still works on CPU.
  - For Word2Vec/FastText token coverage, we average available word vectors; OOV words are skipped for W2V.
  - To match UniEmbed dims (100 + 100 + 512 = 712), we apply PCA to reduce 300-d Word2Vec and FastText to 100-d.
  - The approach and dimensionalities follow the UniEmbed paper’s methodology and block diagram.

"""

import os
import re
import time
import argparse
import warnings
from typing import List, Tuple, Dict

import numpy as np
import pandas as pd

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, roc_curve, auc
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.svm import SVC

import gensim
from gensim.models import KeyedVectors

import fasttext
import tensorflow_hub as hub
import tensorflow as tf

warnings.filterwarnings("ignore", category=UserWarning)
sns.set(style="whitegrid")

DATASET_PATHS = [
    "./dataset/XSS/XSS_dataset.csv",
    "./dataset/SQLi/sqli.csv",
    "./dataset/SQLi/sqliv2.csv",
    "./dataset/SQLi/SQLiV3.csv",
]

# ---------------------------
# Text cleaning and tokenization
# ---------------------------
def clean_text(s: str) -> str:
    """Clean payload text: remove HTML tags, special chars (keep alphanum and common symbols in payloads),
    normalize spaces, lowercase."""
    if s is None:
        return ""
    # Remove HTML tags
    s = re.sub(r"<[^>]+>", " ", s)
    # Remove control chars
    s = re.sub(r"[\r\n\t]", " ", s)
    # Keep common payload symbols; strip exotic unicode
    s = re.sub(r"[^a-zA-Z0-9_\-\.\,\:\;\(\)\[\]\{\}\'\"\@\!\?\=\+\*\%\/\\\|\s]", " ", s)
    # Normalize spaces and lowercase
    s = re.sub(r"\s+", " ", s).strip().lower()
    return s

def tokenize(s: str) -> List[str]:
    """Simple whitespace tokenization; can be replaced with smarter tokenizers if desired."""
    if not s:
        return []
    return s.split()

# ---------------------------
# Embedding loaders
# ---------------------------
def load_use():
    """Load Universal Sentence Encoder model from TF-Hub (512-d)."""
    # Use v4 that outputs 512-d sentence embeddings per the paper’s description.
    # tf.compat.v1.enable_eager_execution()
    use_model = hub.load("https://tfhub.dev/google/universal-sentence-encoder/4")
    return use_model

def load_word2vec(path: str) -> KeyedVectors:
    """Load pre-trained Word2Vec vectors (e.g., GoogleNews 300-d)."""
    print(f"[INFO] Loading Word2Vec from: {path}")
    kv = KeyedVectors.load_word2vec_format(path, binary=True)
    print("[INFO] Word2Vec loaded.")
    return kv

def load_fasttext(path: str):
    """Load pre-trained FastText binary model (300-d)."""
    print(f"[INFO] Loading FastText from: {path}")
    ft = fasttext.load_model(path)
    print("[INFO] FastText loaded.")
    return ft

# ---------------------------
# Sentence embeddings
# ---------------------------
def sentence_embedding_w2v(tokens: List[str], kv: KeyedVectors) -> np.ndarray:
    """Average available Word2Vec vectors over tokens. OOV tokens are skipped."""
    vecs = [kv[t] for t in tokens if t in kv.key_to_index]
    if not vecs:
        return np.zeros(kv.vector_size, dtype=np.float32)
    return np.mean(vecs, axis=0).astype(np.float32)

def sentence_embedding_fasttext(text: str, ft_model) -> np.ndarray:
    """FastText sentence vector by averaging word vectors or using get_sentence_vector (if available)."""
    # fastText’s get_sentence_vector returns a 300-d vector (for supervised); for unsupervised we average word vectors.
    # Use get_sentence_vector for simplicity; it applies subword info and averages.
    vec = ft_model.get_sentence_vector(text)
    return vec.astype(np.float32)

def sentence_embedding_use(use_model, texts: List[str], batch_size: int = 128) -> np.ndarray:
    """Batch USE để tránh OOM."""
    out = []
    for i in range(0, len(texts), batch_size):
        out.append(use_model(texts[i:i+batch_size]).numpy())
    return np.vstack(out).astype(np.float32)

# ---------------------------
# Feature pipeline (UniEmbed)
# ---------------------------
def build_uniembed_features(
    sentences: List[str],
    kv: KeyedVectors,
    ft_model,
    use_model,
    pca_w2v: PCA,
    pca_ft: PCA
) -> np.ndarray:
    """Create UniEmbed feature vectors (712-d): 100-d W2V + 100-d FT + 512-d USE."""
    # Prepare USE embeddings in batch to speed up
    cleaned = [clean_text(s) for s in sentences]
    tokens_list = [tokenize(c) for c in cleaned]

    # W2V sentence embeddings (300-d -> PCA to 100-d)
    w2v_raw = np.vstack([sentence_embedding_w2v(tokens, kv) for tokens in tokens_list])
    w2v_100 = pca_w2v.transform(w2v_raw)

    # FastText sentence embeddings (300-d -> PCA to 100-d)
    ft_raw = np.vstack([sentence_embedding_fasttext(c, ft_model) for c in cleaned])
    ft_100 = pca_ft.transform(ft_raw)

    # USE embeddings (512-d)
    use_512 = sentence_embedding_use(use_model, cleaned)

    # Concatenate: 100 + 100 + 512 = 712
    uniembed = np.hstack([w2v_100, ft_100, use_512]).astype(np.float32)
    return uniembed

def fit_pca_for_projection(
    sentences: List[str],
    kv: KeyedVectors,
    ft_model,
    n_components: int = 100
) -> Tuple[PCA, PCA]:
    """Fit PCA on Word2Vec and FastText sentence vectors to project from 300-d -> 100-d."""
    cleaned = [clean_text(s) for s in sentences]
    tokens_list = [tokenize(c) for c in cleaned]

    w2v_raw = np.vstack([sentence_embedding_w2v(tokens, kv) for tokens in tokens_list])
    ft_raw = np.vstack([sentence_embedding_fasttext(c, ft_model) for c in cleaned])

    pca_w2v = PCA(n_components=n_components, random_state=42).fit(w2v_raw)
    pca_ft = PCA(n_components=n_components, random_state=42).fit(ft_raw)
    return pca_w2v, pca_ft

# ---------------------------
# Evaluation helpers
# ---------------------------
def compute_metrics(y_true, y_pred, y_score=None) -> Dict[str, float]:
    metrics = {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
    }
    if y_score is not None:
        fpr, tpr, _ = roc_curve(y_true, y_score)
        metrics["roc_auc"] = auc(fpr, tpr)
    return metrics

def plot_confusion(y_true, y_pred, title: str, out_path: str):
    cm = confusion_matrix(y_true, y_pred)
    plt.figure(figsize=(4, 3))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", cbar=False)
    plt.title(title)
    plt.xlabel("Predicted")
    plt.ylabel("True")
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()

def plot_roc(y_true, y_score, title: str, out_path: str):
    fpr, tpr, _ = roc_curve(y_true, y_score)
    roc_auc = auc(fpr, tpr)
    plt.figure(figsize=(4, 3))
    plt.plot(fpr, tpr, label=f"AUC = {roc_auc:.4f}")
    plt.plot([0, 1], [0, 1], "k--", lw=1)
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title(title)
    plt.legend(loc="lower right")
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()

# ---------------------------
# Main training flow
# ---------------------------
def main():
    parser = argparse.ArgumentParser(description="Retrain UniEmbed ML models on combined XSS/SQLi datasets.")
    parser.add_argument("--w2v_path", type=str, required=True, help="Path to Word2Vec binary (e.g., GoogleNews .bin.gz).")
    parser.add_argument("--ft_path", type=str, required=True, help="Path to FastText binary (e.g., wiki.en.bin or cc.en.300.bin.gz).")
    parser.add_argument("--test_size", type=float, default=0.2, help="Test split size (default: 0.2).")
    parser.add_argument("--random_state", type=int, default=42, help="Random state (default: 42).")
    parser.add_argument("--mlp_hidden", type=str, default="256,128", help="MLP hidden layers, comma-separated (default: 256,128).")
    parser.add_argument("--out_models", type=str, default="combined_models", help="Directory to save models.")
    parser.add_argument("--out_reports", type=str, default="combined_reports", help="Directory to save reports/plots.")
    args = parser.parse_args()

    os.makedirs(args.out_models, exist_ok=True)
    os.makedirs(args.out_reports, exist_ok=True)

    print("[INFO] Hợp nhất các dataset...")
    all_dfs = []
    for path in DATASET_PATHS:
        try:
            # Đọc CSV, giả định cột Sentence và Label
            df = pd.read_csv(path)
            if "Sentence" not in df.columns or "Label" not in df.columns:
                # Thử đọc lại với header=None nếu không có cột
                df = pd.read_csv(path, header=None)
                # Giả định cột payload là cột thứ 2 (index 1) và label là cột thứ 3 (index 2)
                # Dựa trên XSS_dataset.csv mẫu: cột 1 là index, cột 2 là Sentence, cột 3 là Label
                if df.shape[1] >= 2:
                    df.columns = ["Index", "Sentence", "Label"] + [f"Col{i}" for i in range(2, df.shape[1])]
                    df = df[["Sentence", "Label"]]
                else:
                    raise ValueError(f"Dataset {path} không có cột 'Sentence' và 'Label' rõ ràng.")
            
            all_dfs.append(df)
            print(f"Đã tải {path} ({len(df)} mẫu)")
        except FileNotFoundError:
            print(f"[CẢNH BÁO] Không tìm thấy file: {path}. Bỏ qua.")
        except Exception as e:
            print(f"[LỖI] Lỗi khi đọc file {path}: {e}. Bỏ qua.")

    if not all_dfs:
        raise RuntimeError("Không tìm thấy dataset nào để huấn luyện.")

    combined_df = pd.concat(all_dfs, ignore_index=True).drop_duplicates(subset=["Sentence", "Label"])
    print(f"[INFO] Tổng số mẫu sau khi hợp nhất và loại bỏ trùng lặp: {len(combined_df)}")

    sentences = combined_df["Sentence"].astype(str).tolist()
    labels = combined_df["Label"].astype(int).values

    # Train/test split
    X_train_s, X_test_s, y_train, y_test = train_test_split(
        sentences, labels, test_size=args.test_size, random_state=args.random_state, stratify=labels
    )

    # Load embeddings
    use_model = load_use()
    w2v_kv = load_word2vec(args.w2v_path)
    ft_model = load_fasttext(args.ft_path)

    # Fit PCA to project 300->100 for W2V and FastText using training set
    print("[INFO] Fitting PCA for W2V and FastText projections to 100-d ...")
    pca_w2v, pca_ft = fit_pca_for_projection(X_train_s, w2v_kv, ft_model, n_components=100)
    joblib.dump(pca_w2v, os.path.join(args.out_models, "pca_w2v.pkl"))
    joblib.dump(pca_ft, os.path.join(args.out_models, "pca_ft.pkl"))
    print("[INFO] PCA models saved (pca_w2v.pkl, pca_ft.pkl).")

    # Build UniEmbed features
    print("[INFO] Building UniEmbed features (train) ...")
    X_train = build_uniembed_features(X_train_s, w2v_kv, ft_model, use_model, pca_w2v, pca_ft)
    print("[INFO] Building UniEmbed features (test) ...")
    X_test = build_uniembed_features(X_test_s, w2v_kv, ft_model, use_model, pca_w2v, pca_ft)

    # Scale features
    scaler = StandardScaler(with_mean=True, with_std=True)
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    joblib.dump(scaler, os.path.join(args.out_models, "scaler.pkl"))
    print("[INFO] Scaler saved (scaler.pkl).")

    # Define models
    mlp_layers = tuple(int(x) for x in args.mlp_hidden.split(",") if x.strip())
    models = {
        "mlp": MLPClassifier(hidden_layer_sizes=mlp_layers, activation="relu", solver="adam",
                             max_iter=200, random_state=args.random_state, early_stopping=True),
        "rf": RandomForestClassifier(n_estimators=300, max_depth=None, n_jobs=-1, random_state=args.random_state),
        "svm": SVC(kernel="rbf", C=3.0, gamma="scale", probability=True, random_state=args.random_state),
    }

    metrics_rows = []

    # Train and evaluate base models
    for name, model in models.items():
        print(f"[INFO] Training {name.upper()} ...")
        t0 = time.time()
        model.fit(X_train_scaled, y_train)
        train_time = time.time() - t0

        y_pred = model.predict(X_test_scaled)
        # For ROC, use probability of class 1
        if hasattr(model, "predict_proba"):
            y_score = model.predict_proba(X_test_scaled)[:, 1]
        else:
            # SVM with probability=True will have predict_proba; as fallback use decision_function
            if hasattr(model, "decision_function"):
                scores = model.decision_function(X_test_scaled)
                # Map decision_function scores to [0,1] via logistic transform for visualization
                y_score = 1.0 / (1.0 + np.exp(-scores))
            else:
                y_score = None

        m = compute_metrics(y_test, y_pred, y_score)
        m["model"] = name
        m["train_time_sec"] = train_time
        metrics_rows.append(m)

        # Save model
        joblib.dump(model, os.path.join(args.out_models, f"{name}.pkl"))
        print(f"[INFO] Saved {name}.pkl — Train time: {train_time:.2f}s | "
              f"Acc: {m['accuracy']:.4f}, Prec: {m['precision']:.4f}, Rec: {m['recall']:.4f}, F1: {m['f1']:.4f}")

        # Plots
        plot_confusion(y_test, y_pred, f"Confusion Matrix — {name.upper()}", os.path.join(args.out_reports, f"confusion_{name}.png"))
        if y_score is not None:
            plot_roc(y_test, y_score, f"ROC Curve — {name.upper()}", os.path.join(args.out_reports, f"roc_{name}.png"))

    # Voting classifiers (hard & soft)
    estimators = [(k, models[k]) for k in ["mlp", "rf", "svm"]]
    voting_hard = VotingClassifier(estimators=estimators, voting="hard", n_jobs=-1)
    voting_soft = VotingClassifier(estimators=estimators, voting="soft", n_jobs=-1)

    # Train voting hard
    print("[INFO] Training Voting (hard) ...")
    t0 = time.time()
    voting_hard.fit(X_train_scaled, y_train)
    train_time = time.time() - t0
    y_pred = voting_hard.predict(X_test_scaled)
    # For ROC hard voting, no probability; estimate via averaging proba if available
    y_score = None
    m = compute_metrics(y_test, y_pred, y_score)
    m["model"] = "voting_hard"
    m["train_time_sec"] = train_time
    metrics_rows.append(m)
    joblib.dump(voting_hard, os.path.join(args.out_models, "voting_hard.pkl"))
    print(f"[INFO] Saved voting_hard.pkl — Train time: {train_time:.2f}s | "
          f"Acc: {m['accuracy']:.4f}, Prec: {m['precision']:.4f}, Rec: {m['recall']:.4f}, F1: {m['f1']:.4f}")
    plot_confusion(y_test, y_pred, "Confusion Matrix — Voting (Hard)", os.path.join(args.out_reports, "confusion_voting_hard.png"))

    # Train voting soft
    print("[INFO] Training Voting (soft) ...")
    t0 = time.time()
    voting_soft.fit(X_train_scaled, y_train)
    train_time = time.time() - t0
    y_pred = voting_soft.predict(X_test_scaled)
    # Soft voting proba available
    y_score = voting_soft.predict_proba(X_test_scaled)[:, 1]
    m = compute_metrics(y_test, y_pred, y_score)
    m["model"] = "voting_soft"
    m["train_time_sec"] = train_time
    metrics_rows.append(m)
    joblib.dump(voting_soft, os.path.join(args.out_models, "voting_soft.pkl"))
    print(f"[INFO] Saved voting_soft.pkl — Train time: {train_time:.2f}s | "
          f"Acc: {m['accuracy']:.4f}, Prec: {m['precision']:.4f}, Rec: {m['recall']:.4f}, F1: {m['f1']:.4f}")
    plot_confusion(y_test, y_pred, "Confusion Matrix — Voting (Soft)", os.path.join(args.out_reports, "confusion_voting_soft.png"))
    plot_roc(y_test, y_score, "ROC Curve — Voting (Soft)", os.path.join(args.out_reports, "roc_voting_soft.png"))

    # Save metrics report
    report_df = pd.DataFrame(metrics_rows)[
        ["model", "accuracy", "precision", "recall", "f1", "roc_auc", "train_time_sec"]
    ].fillna({"roc_auc": np.nan})
    report_path = os.path.join(args.out_reports, "metrics_report.csv")
    report_df.to_csv(report_path, index=False)
    print(f"[INFO] Metrics report saved: {report_path}")

    # Print a neat table in console
    print("\n=== Metrics Summary ===")
    print(report_df.to_string(index=False, float_format=lambda x: f"{x:.4f}"))

    print("\n[DONE] All models and artifacts are saved.")

if __name__ == "__main__":
    main()

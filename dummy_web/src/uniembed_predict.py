import os
import re
import string
import joblib
import numpy as np
from typing import List, Tuple, Dict
import tensorflow_hub as hub
import tensorflow as tf
import gensim
import fasttext

# results (2) with replace HTML tags with HTMLTAG
# BASE_OUTPUT_DIRS = [
#     "output_XSS_dataset1_20251115_040730",
#     "output_SQLiV3_1_20251115_043655",
#     "output_sqliv2_20251115_042254",
#     "output_sqli_20251115_040928",
# ]

#results (3) without replace HTML tags
# BASE_OUTPUT_DIRS = [
#     "output_XSS_dataset1_20251115_060410",
#     "output_SQLiV3_1_20251115_063850",
#     "output_sqliv2_20251115_062242",
#     "output_sqli_20251115_060627",
# ]

#results (4) with merged SQL Injection dataset
BASE_OUTPUT_DIRS = [
    "output_XSS_dataset1_20251115_091139",
    "output_sqli_mergedv3_20251115_102935",
]

# Danh sách tất cả 8 mô hình (4 models x 2 datasets)
MODEL_CONFIGS = []
for base_dir in BASE_OUTPUT_DIRS:
    if "XSS" in base_dir:
        ext = ".pkl"
    else:
        ext = ".joblib"

    # for model_name in ["mlp", "rf", "svm", "voting_soft"]:
    for model_name in ["voting_soft"]:
        MODEL_CONFIGS.append({
            "name": f"{base_dir.split('_')[1]}_{model_name}",
            "artifacts_dir": f"./results (4)/{base_dir}/models",
            "model_file": f"{model_name}{ext}"
        })

# ---------------------------
# 1. Text cleaning and tokenization
# ---------------------------
def clean_text(s: str) -> str:
    """
    Tối ưu hóa tiền xử lý payload:
    1. Loại bỏ các ký tự không in được (non-printable) và ký tự điều khiển.
    2. Chuẩn hóa khoảng trắng và chuyển về chữ thường.
    """
    if s is None:
        return ""
    
    # 1. Loại bỏ các ký tự không in được (non-printable) và ký tự điều khiển
    # Giữ lại tất cả các ký tự in được trong bảng mã ASCII
    s = ''.join(filter(lambda x: x in string.printable, s))
    
    # 2. Loại bỏ ký tự xuống dòng và tab (đã được xử lý một phần bởi string.printable, nhưng làm lại để đảm bảo)
    s = re.sub(r"[\r\n\t]", " ", s)
    
    # 3. Chuẩn hóa khoảng trắng và chuyển về chữ thường
    s = re.sub(r"\s+", " ", s).strip().lower()
    
    return s

def tokenize(s: str) -> List[str]:
    """Simple whitespace tokenization."""
    if not s:
        return []
    return s.split()

# ---------------------------
# 2. Embedding functions
# ---------------------------
global W2V_KV, FT_MODEL, USE_MODEL, LOADED_MODELS

W2V_KV = None
FT_MODEL = None
USE_MODEL = None
LOADED_MODELS = [] 

def sentence_embedding_w2v(tokens: List[str], kv: gensim.models.KeyedVectors) -> np.ndarray:
    """Vector trung bình từ Word2Vec (bỏ OOV)."""
    vecs = [kv[t] for t in tokens if t in kv.key_to_index]
    if not vecs:
        return np.zeros(300, dtype=np.float32) 
    return np.mean(vecs, axis=0).astype(np.float32)

def sentence_embedding_fasttext(text: str, ft_model) -> np.ndarray:
    """FastText sentence vector."""
    vec = ft_model.get_sentence_vector(text)
    return vec.astype(np.float32)

def sentence_embedding_use(use_model, texts: List[str]) -> np.ndarray:
    """USE embeddings for a list of sentences (batch)."""
    emb = use_model(texts).numpy().astype(np.float32)
    return emb

def build_uniembed_features(
    sentence: str,
    kv: gensim.models.KeyedVectors,
    ft_model,
    use_model,
    pca_w2v,
    pca_ft
) -> np.ndarray:
    """Create UniEmbed feature vector (712-d) for a single sentence."""
    cleaned = clean_text(sentence)
    tokens = tokenize(cleaned)

    # W2V sentence embeddings (300-d -> PCA to 100-d)
    w2v_raw = sentence_embedding_w2v(tokens, kv).reshape(1, -1)
    w2v_100 = pca_w2v.transform(w2v_raw)

    # FastText sentence embeddings (300-d -> PCA to 100-d)
    ft_raw = sentence_embedding_fasttext(cleaned, ft_model).reshape(1, -1)
    ft_100 = pca_ft.transform(ft_raw)

    # USE embeddings (512-d)
    use_512 = sentence_embedding_use(use_model, [cleaned])

    # Concatenate: 100 + 100 + 512 = 712
    uniembed = np.hstack([w2v_100, ft_100, use_512]).astype(np.float32)
    return uniembed

def load_models(w2v_path: str, ft_path: str):
    """Load tất cả các models và artifacts cần thiết."""
    global W2V_KV, FT_MODEL, USE_MODEL, LOADED_MODELS

    print("[WAF] Đang tải các thành phần UniEmbed...")
    
    # Tải Universal Sentence Encoder (USE)
    tf.compat.v1.enable_eager_execution()
    USE_MODEL = hub.load("./embeddings/use/")
    print("[WAF] Đã tải Universal Sentence Encoder.")

    # Tải Word2Vec
    W2V_KV = gensim.models.KeyedVectors.load_word2vec_format(w2v_path, binary=True)
    print("[WAF] Đã tải Word2Vec.")

    # Tải FastText
    FT_MODEL = fasttext.load_model(ft_path)
    print("[WAF] Đã tải FastText.")

    # Tải Preprocessing Artifacts và Classifiers (16 models)
    for config in MODEL_CONFIGS:
        try:
            artifacts_dir = config["artifacts_dir"]
            model_path = os.path.join(artifacts_dir, config["model_file"])
            
            # Load artifacts (.joblib)
            scaler = joblib.load(os.path.join(artifacts_dir, "scaler.joblib"))
            pca_w2v = joblib.load(os.path.join(artifacts_dir, "pca_w2v.joblib"))
            pca_ft = joblib.load(os.path.join(artifacts_dir, "pca_ft.joblib"))
            
            # Load classifier (.pkl hoặc .joblib)
            classifier = joblib.load(model_path)
            
            LOADED_MODELS.append({
                "name": config["name"],
                "scaler": scaler,
                "pca_w2v": pca_w2v,
                "pca_ft": pca_ft,
                "classifier": classifier
            })
            # print(f"[WAF] Đã tải thành công mô hình: {config['name']}")
        except Exception as e:
            print(f"[WAF LỖI] Không thể tải mô hình {config['name']} từ {model_path}: {e}")
            continue

    if not LOADED_MODELS:
        raise RuntimeError("Không tải được bất kỳ mô hình nào. WAF sẽ bị vô hiệu hóa.")

    print(f"[WAF] Đã tải thành công {len(LOADED_MODELS)} mô hình.")

# ---------------------------
# 3. Main Prediction Function
# ---------------------------
def predict_uniembed(input_string: str) -> int:
    """
    Dự đoán xem input_string là benign (0) hay malicious (1) sử dụng tất cả 16 mô hình UniEmbed đã train.
    
    Kết quả là 1 (malicious) nếu BẤT KỲ mô hình nào dự đoán là 1.
    
    Args:
        input_string: Chuỗi đầu vào (XSS payload, SQLi payload, hoặc chuỗi bình thường).
        
    Returns:
        1 nếu là malicious, 0 nếu là benign.
    """
    if not LOADED_MODELS:
        return 0 

    is_malicious = 0
    
    for model_set in LOADED_MODELS:
        try:
            # 1. Trích xuất UniEmbed features với artifacts tương ứng
            X_raw = build_uniembed_features(
                input_string, W2V_KV, FT_MODEL, USE_MODEL, model_set["pca_w2v"], model_set["pca_ft"]
            )

            # 2. Scale features với scaler tương ứng
            X_scaled = model_set["scaler"].transform(X_raw)

            # 3. Dự đoán
            # Lưu ý: SVM (SVC) cần predict_proba nếu dùng voting soft, nhưng ở đây ta dùng predict()
            # để đơn giản hóa logic cho tất cả các mô hình cơ sở
            prediction = model_set["classifier"].predict(X_scaled)[0]
            
            if prediction == 1:
                is_malicious = 1
                print(f"Phát hiện bởi: {model_set['name']}") # Dùng để debug
                break 

        except Exception as e:
            # Nếu có lỗi trong quá trình dự đoán (ví dụ: lỗi TF), ta coi là benign để không chặn nhầm
            print(f"Lỗi khi dự đoán với mô hình {model_set['name']}: {e}")
            continue

    return is_malicious

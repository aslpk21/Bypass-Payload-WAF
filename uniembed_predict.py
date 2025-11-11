import os
import re
import joblib
import numpy as np
from typing import List, Tuple, Dict

# Thư viện cho Embeddings
import tensorflow_hub as hub
import tensorflow as tf
import gensim
import fasttext

# ----------------------------------------------------------------------
# CẤU HÌNH ĐƯỜNG DẪN - CẦN ĐIỀN ĐÚNG ĐƯỜNG DẪN CỦA BẠN
# ----------------------------------------------------------------------
# Các file Word2Vec và FastText pre-trained embeddings (không có trong file zip)
W2V_PATH = "./embeddings/GoogleNews-vectors-negative300.bin.gz"
FT_PATH = "./embeddings/cc.en.300.bin" # hoặc cc.en.300.bin.gz

# Danh sách các bộ mô hình và artifacts đã train
# Mỗi phần tử là một bộ mô hình (Voting Soft) và các artifacts tiền xử lý tương ứng
MODEL_CONFIGS = [
    {
        "name": "XSS_Model",
        "artifacts_dir": "./trained/output_XSS_dataset_new_20251110_151522/models",
        "model_file": "voting_soft.pkl" # Dựa trên pasted_content_3.txt, XSS dùng .pkl
    },
    {
        "name": "SQLi_V3_Model",
        "artifacts_dir": "./trained/output_SQLiV3_1_20251110_154826/models",
        "model_file": "voting_soft.joblib" # Dựa trên cấu trúc file, SQLi dùng .joblib
    },
    {
        "name": "SQLi_V2_Model",
        "artifacts_dir": "./trained/output_sqliv2_20251110_153311/models",
        "model_file": "voting_soft.joblib"
    },
    {
        "name": "SQLi_Model",
        "artifacts_dir": "./trained/output_sqli_20251110_151739/models",
        "model_file": "voting_soft.joblib"
    },
]

# ---------------------------
# 1. Text cleaning and tokenization (Copy từ Model_Test.py)
# ---------------------------
def clean_text(s: str) -> str:
    """Clean payload text: remove HTML tags, special chars, normalize spaces, lowercase."""
    if s is None:
        return ""
    s = re.sub(r"<[^>]+>", " ", s)
    s = re.sub(r"[\r\n\t]", " ", s)
    s = re.sub(r"[^a-zA-Z0-9_\-\.\,\:\;\(\)\[\]\{\}\'\"\@\!\?\=\+\*\%\/\\\|\s]", " ", s)
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
# Khởi tạo các biến toàn cục để lưu models
global W2V_KV, FT_MODEL, USE_MODEL, LOADED_MODELS

W2V_KV = None
FT_MODEL = None
USE_MODEL = None
LOADED_MODELS = [] # Danh sách các dict: {"name": str, "scaler": obj, "pca_w2v": obj, "pca_ft": obj, "classifier": obj}

def sentence_embedding_w2v(tokens: List[str], kv: gensim.models.KeyedVectors) -> np.ndarray:
    """Vector trung bình từ Word2Vec (bỏ OOV)."""
    vecs = [kv[t] for t in tokens if t in kv.key_to_index]
    if not vecs:
        # Trả về vector 300 chiều (kích thước mặc định của GoogleNews)
        return np.zeros(300, dtype=np.float32) 
    return np.mean(vecs, axis=0).astype(np.float32)

def sentence_embedding_fasttext(text: str, ft_model) -> np.ndarray:
    """FastText sentence vector."""
    # Trả về vector 300 chiều (kích thước mặc định của FastText)
    vec = ft_model.get_sentence_vector(text)
    return vec.astype(np.float32)

def sentence_embedding_use(use_model, texts: List[str]) -> np.ndarray:
    """USE embeddings for a list of sentences (batch)."""
    # USE không hỗ trợ batch size 1, nên ta sẽ dùng list 1 phần tử
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

    print("--- Đang tải các thành phần UniEmbed ---")
    
    # Tải Universal Sentence Encoder (USE)
    try:
        # Tắt eager execution để tránh lỗi khi load model
        tf.compat.v1.enable_eager_execution()
        USE_MODEL = hub.load("https://tfhub.dev/google/universal-sentence-encoder/4")
        print("Đã tải Universal Sentence Encoder.")
    except Exception as e:
        print(f"Lỗi khi tải USE: {e}. Đảm bảo kết nối internet và thư viện TF/TF-Hub.")
        raise

    # Tải Word2Vec
    try:
        W2V_KV = gensim.models.KeyedVectors.load_word2vec_format(w2v_path, binary=True)
        print("Đã tải Word2Vec.")
    except Exception as e:
        print(f"Lỗi khi tải Word2Vec từ {w2v_path}: {e}. Vui lòng kiểm tra đường dẫn.")
        raise

    # Tải FastText
    try:
        FT_MODEL = fasttext.load_model(ft_path)
        print("Đã tải FastText.")
    except Exception as e:
        print(f"Lỗi khi tải FastText từ {ft_path}: {e}. Vui lòng kiểm tra đường dẫn.")
        raise

    # Tải Preprocessing Artifacts và Classifiers
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
            print(f"Đã tải thành công bộ mô hình: {config['name']}")
        except Exception as e:
            print(f"Lỗi khi tải artifacts/classifier cho {config['name']}: {e}")
            # Không raise exception mà chỉ cảnh báo, để các models khác vẫn có thể được tải

    if not LOADED_MODELS:
        raise RuntimeError("Không tải được bất kỳ mô hình nào. Vui lòng kiểm tra đường dẫn.")

    print("--- Tải thành công ---")

# ---------------------------
# 3. Main Prediction Function
# ---------------------------
def predict_uniembed(input_string: str) -> int:
    """
    Dự đoán xem input_string là benign (0) hay malicious (1) sử dụng tất cả các mô hình UniEmbed đã train.
    
    Kết quả là 1 (malicious) nếu BẤT KỲ mô hình nào dự đoán là 1.
    
    Args:
        input_string: Chuỗi đầu vào (XSS payload, SQLi payload, hoặc chuỗi bình thường).
        
    Returns:
        1 nếu là malicious, 0 nếu là benign.
    """
    if not LOADED_MODELS:
        raise RuntimeError("Models chưa được tải. Vui lòng gọi load_models() trước.")

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
            prediction = model_set["classifier"].predict(X_scaled)[0]
            
            if prediction == 1:
                is_malicious = 1
                # print(f"Phát hiện bởi: {model_set['name']}") # Dùng để debug
                break # Chỉ cần 1 mô hình phát hiện là đủ

        except Exception as e:
            print(f"Lỗi khi dự đoán với mô hình {model_set['name']}: {e}")
            continue

    return is_malicious

# ---------------------------
# 4. Example Usage (Chỉ để minh họa)
# ---------------------------
if __name__ == "__main__":
    # *** LƯU Ý QUAN TRỌNG ***
    # Cần thay thế W2V_PATH và FT_PATH bằng đường dẫn thực tế của bạn
    
    print("--- CẢNH BÁO: Cần thay thế W2V_PATH và FT_PATH bằng đường dẫn thực tế ---")
    
    try:
        # Thử tải models (sẽ thất bại nếu không có file W2V/FT)
        load_models(W2V_PATH, FT_PATH)
        
        # Ví dụ dự đoán (chỉ chạy được nếu load_models thành công)
        test_payloads = [
            "This is a normal comment.", # Benign
            "SELECT * FROM users WHERE id = '1' OR '1'='1' --", # SQLi
            "<script>alert('XSS')</script>", # XSS
            "Hello world", # Benign
            "union select 1,2,3 from users", # SQLi
            "javascript:alert(1)" # XSS
        ]
        
        print("\n--- Kết quả dự đoán ---")
        for payload in test_payloads:
            result = predict_uniembed(payload)
            status = "MALICIOUS" if result == 1 else "BENIGN"
            print(f"Payload: {payload[:50]}... -> {result} ({status})")

    except Exception as e:
        print(f"\nKhông thể chạy ví dụ do lỗi: {e}")
        print("Vui lòng thay thế W2V_PATH và FT_PATH bằng đường dẫn chính xác tới các file embeddings.")

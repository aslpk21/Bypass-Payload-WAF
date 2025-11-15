from functools import wraps
from flask import request, abort
from uniembed_predict import predict_uniembed, load_models
import os
import traceback
from dotenv import load_dotenv

load_dotenv()

UNIEMBED_WAF_ENABLED = os.getenv('UNIEMBED_WAF_ENABLED', 'False') == 'True'

def initialize_waf(w2v_path, ft_path):
    global UNIEMBED_WAF_ENABLED

    print(UNIEMBED_WAF_ENABLED)

    if not UNIEMBED_WAF_ENABLED:
        print("[WAF] UNIEMBED_WAF_ENABLED không được đặt thành 'True' trong biến môi trường. Bỏ qua khởi tạo.")
        return

    print("[WAF] Đang khởi tạo các mô hình UniEmbed...")
    try:
        load_models(w2v_path, ft_path)
        print("[WAF] Khởi tạo thành công. WAF đã được kích hoạt.")
    except Exception as e:
        UNIEMBED_WAF_ENABLED = False
        print(f"[WAF LỖI] Không thể tải mô hình UniEmbed. WAF đã bị vô hiệu hóa. Lỗi: {e}")

def waf_protect(check_forms=True, check_args=True, check_json=True, fields=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not UNIEMBED_WAF_ENABLED:
                return f(*args, **kwargs)

            payloads_to_check = []

            if fields:
                for field in fields:
                    value = request.form.get(field)
                    if value is not None:
                        payloads_to_check.append(value)

            else:
                if check_forms and request.form:
                    payloads_to_check.extend(request.form.values())
                if check_args and request.args:
                    payloads_to_check.extend(request.args.values())
                if check_json and request.is_json:
                    json_data = request.get_json()
                    if isinstance(json_data, dict):
                        payloads_to_check.extend(json_data.values())
                    elif isinstance(json_data, list):
                        payloads_to_check.extend(json_data)
                    else:
                        payloads_to_check.append(str(json_data))

            for payload in payloads_to_check:
                if not isinstance(payload, str):
                    continue
                prediction = predict_uniembed(payload)
                if prediction == 1:
                    print(f"[WAF] MALICIOUS: {payload[:100]}...")
                    abort(403, description="Malicious input detected.")

            return f(*args, **kwargs)
        return decorated_function
    return decorator

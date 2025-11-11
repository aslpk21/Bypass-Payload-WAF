from functools import wraps
from flask import request, abort
from uniembed_predict import predict_uniembed, load_models
import os
import traceback
from dotenv import load_dotenv

load_dotenv()

UNIEMBED_WAF_ENABLED = os.getenv('UNIEMBED_WAF_ENABLED', 'False') == 'True'

def initialize_waf(w2v_path, ft_path):
    """
    Tải tất cả các mô hình UniEmbed cần thiết khi ứng dụng Flask khởi động.
    Hàm này chỉ nên được gọi một lần.
    """
    global UNIEMBED_WAF_ENABLED

    print(UNIEMBED_WAF_ENABLED)

    if not UNIEMBED_WAF_ENABLED:
        print("[WAF] UNIEMBED_WAF_ENABLED không được đặt thành 'True' trong biến môi trường. Bỏ qua khởi tạo.")
        return

    print("[WAF] Đang khởi tạo các mô hình UniEmbed... Quá trình này có thể mất vài phút.")
    try:
        load_models(w2v_path, ft_path)
        print("[WAF] Khởi tạo thành công. WAF đã được kích hoạt.")
    except Exception as e:
        UNIEMBED_WAF_ENABLED = False
        print(f"[WAF LỖI] Không thể tải mô hình UniEmbed. WAF đã bị vô hiệu hóa. Lỗi: {e}")

# --- Decorator bảo vệ route ---
def waf_protect(check_forms=True, check_args=True, check_json=True):
    """
    Decorator để kiểm tra dữ liệu đầu vào của một request bằng UniEmbed.
    Nếu phát hiện malicious, request sẽ bị chặn với lỗi 403 Forbidden.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not UNIEMBED_WAF_ENABLED:
                # Nếu WAF bị tắt, bỏ qua kiểm tra
                return f(*args, **kwargs)

            # Lấy tất cả dữ liệu từ request để kiểm tra
            payloads_to_check = []
            if check_forms and request.form:
                payloads_to_check.extend(request.form.values())
            if check_args and request.args:
                payloads_to_check.extend(request.args.values())
            if check_json and request.is_json:
                # Xử lý trường hợp JSON là một dictionary
                json_data = request.get_json()
                if isinstance(json_data, dict):
                    payloads_to_check.extend(json_data.values())
                # Xử lý trường hợp JSON là một list hoặc giá trị đơn lẻ
                elif isinstance(json_data, list):
                    payloads_to_check.extend(json_data)
                else:
                    payloads_to_check.append(str(json_data))

            # Kiểm tra từng payload
            for payload in payloads_to_check:
                if not isinstance(payload, str):
                    continue # Bỏ qua nếu không phải là chuỗi
                
                prediction = predict_uniembed(payload)
                if prediction == 1:
                    print(f"[WAF] PHÁT HIỆN MALICIOUS PAYLOAD: {payload[:100]}...")
                    abort(403, description="Malicious input detected.") # Chặn request
            
            # Nếu tất cả đều an toàn, cho phép request tiếp tục
            return f(*args, **kwargs)
        return decorated_function
    return decorator

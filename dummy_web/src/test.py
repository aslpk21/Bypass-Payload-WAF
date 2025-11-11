import csv
import requests
import argparse
import sys
import libsession
import time
from flask import request, g
from getpass import getpass

# Cấu hình URL dựa trên vulpy.py (mặc định chạy trên port 5000)
BASE_URL = 'http://127.0.1.1:5000'
LOGIN_URL = f'{BASE_URL}/user/login'
POSTS_URL = f'{BASE_URL}/'

def login_and_get_session(username, password):
    """
    Login và lấy session cookie để test XSS.
    """
    session = requests.Session()
    
    try:
        # POST đến /user/login với form data
        login_data = {
            'username': username,
            'password': password
        }
        
        r = session.post(LOGIN_URL, data=login_data, allow_redirects=False)
        
        # Kiểm tra login thành công (302 redirect)
        if r.status_code == 302:
            print(f"✅ Login thành công với user: {username}")
            # Session cookie đã được lưu trong session object
            return session
        else:
            print(f"❌ Login thất bại: Status {r.status_code}")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Lỗi kết nối: {e}")
        return None
    
def run_sqli_tests(csv_filename, payload_field, static_value):
    """Test SQL Injection."""
    print(f"\n--- 🚀 TEST SQLI trên {LOGIN_URL} ---")
    print(f"CSV: {csv_filename} | Field: {payload_field}")
    
    results = {'success': [], 'sql_error': [], 'blocked': []}
    
    try:
        with open(csv_filename, mode='r', encoding='utf-16') as f:
            reader = csv.DictReader(f)
            
            if 'Sentence' not in reader.fieldnames:
                print(f"❌ CSV phải có cột 'Sentence'")
                return

            for i, row in enumerate(reader, 1):
                payload = row['Sentence']
                print(f"\n[{i}] {payload[:60]}...")

                sqli_data = {
                    payload_field: payload,
                    'password' if payload_field == 'username' else 'username': static_value
                }
                
                try:
                    r = requests.post(LOGIN_URL, data=sqli_data, timeout=10, allow_redirects=False)
                    status = r.status_code
                    login_status = r.headers.get('X-Login-Status', 'N/A')
                    
                    print(f"  Status: {status} | {login_status}")
                    
                    if status == 302:
                        print("  🚨 BYPASS!")
                        results['success'].append(payload)
                    elif status == 500:
                        print("  🔴 SQL ERROR!")
                        results['sql_error'].append(payload)
                    else:
                        results['blocked'].append(payload)
                    
                    time.sleep(0.05)
                    
                except Exception as e:
                    print(f"  ❌ {e}")

        # Summary
        print("\n" + "="*70)
        print("📊 KẾT QUẢ SQLI")
        print("="*70)
        print(f"🚨 Bypass: {len(results['success'])}")
        print(f"🔴 SQL Errors: {len(results['sql_error'])}")
        print(f"✅ Blocked: {len(results['blocked'])}")

    except Exception as e:
        print(f"❌ Lỗi: {e}")
        
def run_xss_tests(csv_filename):
    """
    Chạy test XSS vào endpoint /posts/ (POST form với 'text' field),
    rồi kiểm tra stored XSS bằng GET /posts/.
    """
    import csv, time, requests

    print(f"\n--- 🚀 Bắt đầu test XSS trên {BASE_URL} ---")
    print(f"File CSV: {csv_filename}")
    
    # Yêu cầu login
    print("\n🔑 Yêu cầu thông tin đăng nhập để test XSS:")
    username = input("Username: ")
    password = input("Password: ")
    
    session = login_and_get_session(username, password)
    
    if not session:
        print("❌ Không thể login. Hủy test XSS.")
        return
    
    results = {
        'success': [],      # 200/302 - Payload đã được post (server nhận)
        'reflected': [],    # payload xuất hiện ngay trong response POST (hiếm)
        'stored': [],       # payload xuất hiện trên trang /posts/ sau khi post
        'blocked': [],      # 401/403 - Bị chặn
        'error': []         # 500 - Lỗi server
    }
    
    try:
        with open(csv_filename, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            
            if 'Sentence' not in reader.fieldnames:
                print(f"Lỗi: File CSV phải có cột 'Sentence'.")
                return

            for i, row in enumerate(reader, 1):
                payload = row['Sentence']
                print(f"\n[Test {i}] Payload: {payload[:70]}...")
                try:
                    # POST form data đến endpoint /posts/
                    # Theo modposts.py: text = request.form.get('text')
                    xss_data = {'text': payload}
                    
                    post_url = f'{BASE_URL}/posts/'  # <-- sửa: gửi tới /posts/
                    # thêm headers cơ bản (nếu cần)
                    headers = {'Referer': f'{BASE_URL}/posts/'}
                    
                    r = session.post(post_url, data=xss_data, headers=headers, timeout=10, allow_redirects=False)
                    status = r.status_code
                    
                    print(f"  POST -> {post_url}  Status: {status}")
                    
                    # Phân loại
                    if status in [200, 302]:
                        print("  ✅ Payload đã được post (server trả về 200/302).")
                        results['success'].append(payload)
                        
                        # Nếu POST trả về 200 và payload xuất hiện trong response -> reflected
                        if status == 200 and payload in r.text:
                            print("  🚨 REFLECTED XSS - Payload xuất hiện trong POST response!")
                            results['reflected'].append(payload)
                        
                        # Kiểm tra stored XSS: GET trang /posts/ (sau redirect nếu có)
                        try:
                            # Một chút delay để server cập nhật DB
                            time.sleep(0.15)
                            view_url = f'{BASE_URL}/posts/'
                            rv = session.get(view_url, timeout=10, allow_redirects=True)
                            if rv.status_code == 200 and payload in rv.text:
                                print("  🚨 STORED XSS - Payload xuất hiện trên /posts/ !")
                                results['stored'].append(payload)
                            else:
                                print("  ℹ️ Payload không thấy trên /posts/ (chưa stored or sanitized).")
                        except requests.exceptions.RequestException as e:
                            print(f"  ⚠️ Không thể GET /posts/ để kiểm tra stored XSS: {e}")
                    
                    elif status in [401, 403]:
                        print("  🔒 Blocked/Unauthorized")
                        results['blocked'].append(payload)
                    
                    elif status == 500:
                        print("  🔴 Server Error")
                        results['error'].append(payload)
                    
                    else:
                        # Các status code khác: log ra
                        print(f"  ℹ️ HTTP {status} (không phải 200/302/401/403/500).")
                    
                    # tránh gửi quá nhanh
                    time.sleep(0.05)
                    
                except requests.exceptions.RequestException as e:
                    print(f"  ❌ Error: {e}")

        # Tổng kết
        print("\n" + "="*80)
        print("📋 TỔNG KẾT XSS")
        print("="*80)
        print(f"✅ Payload posted: {len(results['success'])}")
        print(f"🚨 Reflected (in POST response): {len(results['reflected'])}")
        print(f"🚨 Stored (found on /posts/): {len(results['stored'])}")
        print(f"🔒 Blocked: {len(results['blocked'])}")
        print(f"🔴 Server Errors: {len(results['error'])}")
        
        if results['success']:
            print(f"\n✅ {len(results['success'])} payload đã được post thành công.")
            if results['stored']:
                print(f"⚠️ {len(results['stored'])} payload gây stored XSS. Kiểm tra ngay trên {BASE_URL}/posts/")
            else:
                print("💡 Không tìm thấy stored XSS tự động; bạn có thể kiểm tra thủ công:")
                print(f"   1. Mở browser và truy cập: {BASE_URL}/posts/")
                print(f"   2. Login với user: {username}")
                print("   3. Xem các post và kiểm tra DevTools Console / HTML source")
    
    except FileNotFoundError:
        print(f"Lỗi: Không tìm thấy file '{csv_filename}'")
    except Exception as e:
        print(f"Lỗi: {e}")
        import traceback
        traceback.print_exc()


def main():
    parser = argparse.ArgumentParser(
        description="Gửi payload từ CSV đến các endpoint của Vulnpy.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    # Đối số bắt buộc
    parser.add_argument('attack_type', 
                        choices=['SQLI', 'XSS'], 
                        help="Loại tấn công:\n"
                             "  SQLI - Test endpoint /user/login\n"
                             "  XSS  - Test endpoint /api/post")
    
    parser.add_argument('csv_file', 
                        help="Đường dẫn đến file .csv chứa payload.")
    
    # Nhóm đối số chỉ dành cho SQLI
    sqli_group = parser.add_argument_group('Tùy chọn cho SQLI')
    sqli_group.add_argument('--payload-field', 
                            choices=['username', 'password'], 
                            default='username', 
                            help="Trường nào sẽ nhận payload từ CSV (mặc định: username)")
    
    sqli_group.add_argument('--static-value', 
                            default='dummy_password', 
                            help="Giá trị tĩnh cho trường *không* nhận payload (mặc định: 'dummy_password')")
    
    args = parser.parse_args()

    # --- Điều hướng logic dựa trên attack_type ---
    
    if args.attack_type == 'SQLI':
        run_sqli_tests(args.csv_file, args.payload_field, args.static_value)
        
    elif args.attack_type == 'XSS':
        run_xss_tests(args.csv_file)
            
    print("\n--- ✅ Tất cả bài test đã hoàn thành ---")

if __name__ == "__main__":
    main()
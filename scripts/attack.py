import requests
import argparse
import time
import os
from pathlib import Path

BASE_URL = 'http://127.0.1.1:5000'
LOGIN_URL = f'{BASE_URL}/user/login'
POSTS_URL = f'{BASE_URL}/posts/'

USERNAME = 'elliot'
PASSWORD = 'something'

# Định nghĩa các file encode cho từng loại
ENCODE_FILES = {
    '1': {  # XSS
        'name': 'XSS',
        'path': 'dataset_txt/XSS',
        'files': [
            # 'base64.txt',
            # 'double_url_encode.txt',
            # 'html_decimal.txt',
            # 'html_hex.txt',
            # 'js_hex.txt',
            # 'js_unicode.txt',
            # 'url_encode.txt'
            'XSS.txt'
        ]
    },
    '2': {  # SQLi
        'name': 'SQLi',
        'path': 'dataset_txt/SQLi',
        'files': [
            'sqliv2.txt'
            # 'base64encode.txt'
            # 'decentities.txt',
            # 'hexentities.txt',
            # 'charencode.txt',
            # 'charunicodeencode.txt',
            # 'chardoubleencode.txt'
        ]
    }
}

def login_and_get_session():
    session = requests.Session()
    
    try:
        login_data = {
            'username': USERNAME,
            'password': PASSWORD
        }
        
        print(f"[*] Authenticating as user: {USERNAME}")
        r = session.post(LOGIN_URL, data=login_data, allow_redirects=False)
        
        if r.status_code == 302:
            print(f"[+] Authentication successful")
            return session
        else:
            print(f"[-] Authentication failed: HTTP {r.status_code}")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"[-] Connection error: {e}")
        return None

def detect_file_encoding(filename):
    encodings = ['utf-8', 'utf-16', 'latin-1']
    
    for encoding in encodings:
        try:
            with open(filename, mode='r', encoding=encoding) as f:
                f.read(1024)  # Try reading first 1KB
                return encoding
        except (UnicodeDecodeError, UnicodeError):
            continue
    
    return 'utf-8'

def test_single_file(session, file_path, attack_type):
    """
    Test payloads from a single file.
    Returns dict with bypassed and blocked payloads.
    """
    filename = os.path.basename(file_path)
    print(f"\n{'='*80}")
    print(f"Testing File: {filename}")
    print(f"{'='*80}")
    
    results = {
        'bypassed': [],
        'blocked': []
    }
    
    # Detect encoding
    encoding = detect_file_encoding(file_path)
    print(f"[*] Detected file encoding: {encoding}")
    
    try:
        with open(file_path, mode='r', encoding=encoding, errors='ignore') as f:
            payloads = [line.strip() for line in f if line.strip()]
            
            if not payloads:
                print(f"[-] Warning: No payloads found in file")
                return results
            
            print(f"[*] Total payloads: {len(payloads)}\n")

            for i, payload in enumerate(payloads, 1):
                # Show progress every 100 payloads
                if i % 100 == 0:
                    print(f"[*] Progress: {i}/{len(payloads)} payloads tested...")
                
                try:
                    # POST payload to blog endpoint
                    xss_data = {'text': payload}
                    headers = {'Referer': POSTS_URL}
                    
                    r = session.post(POSTS_URL, data=xss_data, headers=headers, 
                                   timeout=10, allow_redirects=False)
                    status = r.status_code
                    response_text = r.text
                    
                    # Check if blocked (403 + "Forbidden" in response)
                    if status == 403 and "Forbidden" in response_text:
                        results['blocked'].append(payload)
                    else:
                        print(f"  [✓] BYPASSED [{i}]: {payload[:100]}...")
                        results['bypassed'].append(payload)
                    
                except requests.exceptions.RequestException as e:
                    print(f"  [-] Request error [{i}]: {e}")
                    results['blocked'].append(payload)
                
    except FileNotFoundError:
        print(f"[-] Error: File '{file_path}' not found")
    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback
        traceback.print_exc()
    
    return results

def save_bypassed_payloads(output_folder, filename, bypassed_payloads, stats):
    """
    Save bypassed payloads and statistics to a file in the output folder.
    """
    # Create output folder if it doesn't exist
    os.makedirs(output_folder, exist_ok=True)
    
    output_path = os.path.join(output_folder, filename)
    
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            # Write statistics header
            f.write("="*80 + "\n")
            f.write(f"File: {filename} - Summary\n")
            f.write("="*80 + "\n")
            f.write(f"Total Tested: {stats['total_count']}\n")
            f.write(f"Bypassed: {stats['bypassed_count']}\n")
            f.write(f"Blocked: {stats['blocked_count']}\n")
            f.write(f"Bypass Rate: {stats['bypass_rate']:.2f}%\n")
            f.write("="*80 + "\n\n")
            
            # Write bypassed payloads
            f.write("BYPASSED PAYLOADS:\n")
            f.write("-"*80 + "\n\n")
            for payload in bypassed_payloads:
                f.write(payload + '\n')
        
        print(f"[+] Saved {len(bypassed_payloads)} bypassed payloads to: {output_path}")
        return True
    except Exception as e:
        print(f"[-] Error saving file {output_path}: {e}")
        return False

def run_payload_tests(attack_type, output_folder):
    """
    Test payloads by posting to /posts/ endpoint for multiple files.
    """
    if attack_type not in ENCODE_FILES:
        print(f"[-] Invalid attack type. Use 1 for XSS or 2 for SQLi")
        return
    
    config = ENCODE_FILES[attack_type]
    
    print(f"\n{'='*80}")
    print(f"PAYLOAD TESTING - {config['name']} Attack")
    print(f"{'='*80}")
    print(f"Target URL: {POSTS_URL}")
    print(f"Encode Folder: {config['path']}")
    print(f"Output Folder: {output_folder}")
    print(f"Credentials: {USERNAME}:{PASSWORD}")
    print(f"Total Files: {len(config['files'])}")
    print(f"{'='*80}\n")
    
    # Authenticate once for all tests
    session = login_and_get_session()
    
    if not session:
        print("[-] Authentication failed. Aborting test.")
        return
    
    overall_results = {
        'total_bypassed': 0,
        'total_blocked': 0,
        'total_tested': 0,
        'files_processed': 0
    }
    
    # Test each file
    for file_name in config['files']:
        file_path = os.path.join(config['path'], file_name)
        
        if not os.path.exists(file_path):
            print(f"[-] Warning: File not found: {file_path}")
            continue
        
        # Test the file
        results = test_single_file(session, file_path, config['name'])
        
        # Update overall statistics
        bypassed_count = len(results['bypassed'])
        blocked_count = len(results['blocked'])
        total_count = bypassed_count + blocked_count
        
        overall_results['total_bypassed'] += bypassed_count
        overall_results['total_blocked'] += blocked_count
        overall_results['total_tested'] += total_count
        overall_results['files_processed'] += 1
        
        # Print file summary
        bypass_rate = (bypassed_count / total_count * 100) if total_count > 0 else 0
        print(f"\n{'='*80}")
        print(f"File: {file_name} - Summary")
        print(f"{'='*80}")
        print(f"Total Tested: {total_count}")
        print(f"Bypassed: {bypassed_count}")
        print(f"Blocked: {blocked_count}")
        print(f"Bypass Rate: {bypass_rate:.2f}%")
        print(f"{'='*80}\n")
        
        # Prepare statistics for saving
        stats = {
            'total_count': total_count,
            'bypassed_count': bypassed_count,
            'blocked_count': blocked_count,
            'bypass_rate': bypass_rate
        }
        
        # Save bypassed payloads to output folder with statistics
        if results['bypassed']:
            save_bypassed_payloads(output_folder, file_name, results['bypassed'], stats)
        else:
            print(f"[*] No bypassed payloads for {file_name}")
    
    # Print overall summary
    overall_bypass_rate = (overall_results['total_bypassed'] / overall_results['total_tested'] * 100) if overall_results['total_tested'] > 0 else 0
    
    print("\n" + "="*80)
    print(f"OVERALL TEST RESULTS - {config['name']} Attack")
    print("="*80)
    print(f"Files Processed: {overall_results['files_processed']}/{len(config['files'])}")
    print(f"Total Payloads Tested: {overall_results['total_tested']}")
    print(f"Total Bypassed: {overall_results['total_bypassed']}")
    print(f"Total Blocked: {overall_results['total_blocked']}")
    print(f"Overall Bypass Rate: {overall_bypass_rate:.2f}%")
    print("="*80)

def main():
    parser = argparse.ArgumentParser(
        description="Payload Testing Tool for XSS/SQLi Attacks",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  # Test XSS payloads and save results to 'xss_results' folder
  python script.py 1 xss_results
  
  # Test SQLi payloads and save results to 'sqli_results' folder
  python script.py 2 sqli_results
        """
    )
    
    parser.add_argument('attack_type', 
                        choices=['1', '2'],
                        help="Attack type: 1 = XSS, 2 = SQLi")
    
    parser.add_argument('output_folder',
                        help="Output folder to save bypassed payloads")
    
    args = parser.parse_args()
    
    run_payload_tests(args.attack_type, args.output_folder)
    
    print("\n" + "="*80)
    print("TEST EXECUTION COMPLETED")
    print("="*80)

if __name__ == "__main__":
    main()
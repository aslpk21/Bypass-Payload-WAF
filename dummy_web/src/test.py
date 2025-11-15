import csv
import requests
import argparse
import sys
import time
from getpass import getpass

# Configuration URL based on vulpy.py (default runs on port 5000)
BASE_URL = 'http://127.0.1.1:5000'
LOGIN_URL = f'{BASE_URL}/user/login'
POSTS_URL = f'{BASE_URL}/'

def login_and_get_session(username, password):
    """
    Authenticate and obtain session cookie for XSS testing.
    """
    session = requests.Session()
    
    try:
        # POST to /user/login with form data
        login_data = {
            'username': username,
            'password': password
        }
        
        r = session.post(LOGIN_URL, data=login_data, allow_redirects=False)
        
        # Check for successful login (302 redirect)
        if r.status_code == 302:
            print(f"[+] Authentication successful for user: {username}")
            # Session cookie is stored in session object
            return session
        else:
            print(f"[-] Authentication failed: HTTP {r.status_code}")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"[-] Connection error: {e}")
        return None
    
def run_sqli_tests(csv_filename, payload_field, static_value):
    """Test SQL Injection vulnerabilities."""
    print(f"\n{'='*70}")
    print(f"SQL INJECTION TEST - Target: {LOGIN_URL}")
    print(f"{'='*70}")
    print(f"CSV File: {csv_filename}")
    print(f"Injection Field: {payload_field}")
    print(f"Static Value: {static_value}")
    print(f"{'='*70}\n")
    
    results = {
        'bypass': [],
        'sql_error': [],
        'blocked': []
    }
    
    try:
        with open(csv_filename, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            
            if 'Sentence' not in reader.fieldnames:
                print(f"[-] Error: CSV must contain 'Sentence' column")
                return

            for i, row in enumerate(reader, 1):
                payload = row['Sentence']
                print(f"[Test {i}] Payload: {payload[:60]}...")

                sqli_data = {
                    payload_field: payload,
                    'password' if payload_field == 'username' else 'username': static_value
                }
                
                try:
                    r = requests.post(LOGIN_URL, data=sqli_data, timeout=10, allow_redirects=False)
                    status = r.status_code
                    login_status = r.headers.get('X-Login-Status', 'N/A')
                    
                    print(f"  Response: HTTP {status} | Login-Status: {login_status}")
                    
                    if status == 302:
                        print("  [!] AUTHENTICATION BYPASS DETECTED")
                        results['bypass'].append(payload)
                    elif status == 500:
                        print("  [!] SQL ERROR - Potential vulnerability")
                        results['sql_error'].append(payload)
                    else:
                        results['blocked'].append(payload)
                    
                    time.sleep(0.05)
                    
                except Exception as e:
                    print(f"  [-] Request failed: {e}")

        # Summary
        print("\n" + "="*70)
        print("SQL INJECTION TEST RESULTS")
        print("="*70)
        print(f"Authentication Bypass: {len(results['bypass'])}")
        print(f"SQL Errors Triggered: {len(results['sql_error'])}")
        print(f"Blocked/Failed: {len(results['blocked'])}")
        
        if results['bypass']:
            print(f"\n[!] CRITICAL: {len(results['bypass'])} payload(s) successfully bypassed authentication")
            print("\nSuccessful Bypass Payloads:")
            print("-" * 70)
            for idx, payload in enumerate(results['bypass'], 1):
                print(f"{idx}. {payload}")
        
        if results['sql_error']:
            print(f"\n[!] WARNING: {len(results['sql_error'])} payload(s) triggered SQL errors")
            print("\nSQL Error Payloads:")
            print("-" * 70)
            for idx, payload in enumerate(results['sql_error'], 1):
                print(f"{idx}. {payload}")

    except Exception as e:
        print(f"[-] Error: {e}")
        
def run_xss_tests(csv_filename):
    """
    Test XSS vulnerabilities by posting to /posts/ endpoint,
    then checking for stored XSS via GET /posts/.
    """
    print(f"\n{'='*70}")
    print(f"CROSS-SITE SCRIPTING TEST - Target: {BASE_URL}")
    print(f"{'='*70}")
    print(f"CSV File: {csv_filename}")
    print(f"{'='*70}\n")
    
    # Request authentication credentials
    print("[*] Authentication required for XSS testing")
    username = input("Username: ")
    password = getpass("Password: ")
    
    session = login_and_get_session(username, password)
    
    if not session:
        print("[-] Authentication failed. Aborting XSS test.")
        return
    
    results = {
        'success': [],      # 200/302 - Payload accepted by server
        'reflected': [],    # Payload appears immediately in POST response
        'stored': [],       # Payload appears on /posts/ after posting
        'blocked': [],      # 401/403 - Request blocked
        'error': []         # 500 - Server error
    }
    
    try:
        with open(csv_filename, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            
            if 'Sentence' not in reader.fieldnames:
                print(f"[-] Error: CSV must contain 'Sentence' column")
                return

            for i, row in enumerate(reader, 1):
                payload = row['Sentence']
                print(f"\n[Test {i}] Payload: {payload[:70]}...")
                try:
                    # POST form data to /posts/ endpoint
                    xss_data = {'text': payload}
                    post_url = f'{BASE_URL}/posts/'
                    headers = {'Referer': f'{BASE_URL}/posts/'}
                    
                    r = session.post(post_url, data=xss_data, headers=headers, timeout=10, allow_redirects=False)
                    status = r.status_code
                    
                    print(f"  POST -> {post_url}  Response: HTTP {status}")
                    
                    # Classify response
                    if status in [200, 302]:
                        print("  [+] Payload accepted by server")
                        results['success'].append(payload)
                        
                        # Check for reflected XSS in POST response
                        if status == 200 and payload in r.text:
                            print("  [!] REFLECTED XSS DETECTED - Payload in POST response")
                            results['reflected'].append(payload)
                        
                        # Check for stored XSS by fetching /posts/
                        try:
                            time.sleep(0.15)
                            view_url = f'{BASE_URL}/posts/'
                            rv = session.get(view_url, timeout=10, allow_redirects=True)
                            if rv.status_code == 200 and payload in rv.text:
                                print("  [!] STORED XSS DETECTED - Payload found on /posts/")
                                results['stored'].append(payload)
                            else:
                                print("  [*] Payload not found on /posts/ (sanitized or filtered)")
                        except requests.exceptions.RequestException as e:
                            print(f"  [-] Unable to verify stored XSS: {e}")
                    
                    elif status in [401, 403]:
                        print("  [-] Request blocked or unauthorized")
                        results['blocked'].append(payload)
                    
                    elif status == 500:
                        print("  [!] Server error triggered")
                        results['error'].append(payload)
                    
                    else:
                        print(f"  [*] Unexpected response: HTTP {status}")
                    
                    time.sleep(0.05)
                    
                except requests.exceptions.RequestException as e:
                    print(f"  [-] Request error: {e}")

        # Summary
        print("\n" + "="*80)
        print("CROSS-SITE SCRIPTING TEST RESULTS")
        print("="*80)
        print(f"Payloads Accepted: {len(results['success'])}")
        print(f"Reflected XSS: {len(results['reflected'])}")
        print(f"Stored XSS: {len(results['stored'])}")
        print(f"Blocked: {len(results['blocked'])}")
        print(f"Server Errors: {len(results['error'])}")
        
        if results['reflected']:
            print(f"\n[!] CRITICAL: {len(results['reflected'])} reflected XSS vulnerability detected")
            print("\nReflected XSS Payloads:")
            print("-" * 80)
            for idx, payload in enumerate(results['reflected'], 1):
                print(f"{idx}. {payload}")
        
        if results['stored']:
            print(f"\n[!] CRITICAL: {len(results['stored'])} stored XSS vulnerability detected")
            print("\nStored XSS Payloads:")
            print("-" * 80)
            for idx, payload in enumerate(results['stored'], 1):
                print(f"{idx}. {payload}")
            print(f"\n[*] Manual verification recommended: {BASE_URL}/posts/")
        elif results['success']:
            print(f"\n[*] {len(results['success'])} payload(s) accepted but no automatic XSS detection")
            print(f"[*] Manual verification recommended:")
            print(f"    1. Open browser and navigate to: {BASE_URL}/posts/")
            print(f"    2. Login with user: {username}")
            print(f"    3. Check posts and inspect DevTools Console / HTML source")
    
    except FileNotFoundError:
        print(f"[-] Error: File '{csv_filename}' not found")
    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback
        traceback.print_exc()


def main():
    parser = argparse.ArgumentParser(
        description="Send payloads from CSV to Vulnpy endpoints for security testing.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    # Required arguments
    parser.add_argument('attack_type', 
                        choices=['SQLI', 'XSS'], 
                        help="Attack type:\n"
                             "  SQLI - Test /user/login endpoint\n"
                             "  XSS  - Test /posts/ endpoint")
    
    parser.add_argument('csv_file', 
                        help="Path to CSV file containing payloads.")
    
    # SQLI-specific options
    sqli_group = parser.add_argument_group('SQLI Options')
    sqli_group.add_argument('--payload-field', 
                            choices=['username', 'password'], 
                            default='username', 
                            help="Field to receive payload from CSV (default: username)")
    
    sqli_group.add_argument('--static-value', 
                            default='dummy_password', 
                            help="Static value for non-payload field (default: 'dummy_password')")
    
    args = parser.parse_args()

    # Route logic based on attack_type
    if args.attack_type == 'SQLI':
        run_sqli_tests(args.csv_file, args.payload_field, args.static_value)
        
    elif args.attack_type == 'XSS':
        run_xss_tests(args.csv_file)
            
    print("\n" + "="*70)
    print("TEST EXECUTION COMPLETED")
    print("="*70)

if __name__ == "__main__":
    main()
import requests
import argparse
import time
import os
import json
import statistics
from datetime import datetime
from pathlib import Path

# Target configurations for different WAFs
TARGET_CONFIGS = {
    'uniembed': {
        'name': 'UniEmbed WAF',
        'base_url': 'http://127.0.0.1:5000',
        'description': 'AI-based WAF running directly on Flask app'
    },
    'modsecurity': {
        'name': 'ModSecurity CRS',
        'base_url': 'http://127.0.0.1:8080',
        'description': 'OWASP ModSecurity CRS via Docker reverse proxy'
    }
}

# Default target (can be overridden by --target argument)
DEFAULT_TARGET = 'uniembed'

# These will be set based on target selection
BASE_URL = None
LOGIN_URL = None
POSTS_URL = None

USERNAME = 'elliot'
PASSWORD = 'something'

def set_target(target_name):
    """Set the target WAF configuration."""
    global BASE_URL, LOGIN_URL, POSTS_URL
    
    if target_name not in TARGET_CONFIGS:
        print(f"[-] Invalid target: {target_name}")
        print(f"    Available targets: {', '.join(TARGET_CONFIGS.keys())}")
        return False
    
    config = TARGET_CONFIGS[target_name]
    BASE_URL = config['base_url']
    LOGIN_URL = f'{BASE_URL}/user/login'
    POSTS_URL = f'{BASE_URL}/posts/'
    
    print(f"[*] Target: {config['name']}")
    print(f"[*] URL: {BASE_URL}")
    print(f"[*] Description: {config['description']}")
    return True

# Định nghĩa các file encode cho từng loại
ENCODE_FILES = {
    '1': {  # XSS
        'name': 'XSS',
        'path': 'dataset_txt/XSS/encode2',
        'files': [
            'base64.txt',
            'double_url_encode.txt',
            'html_decimal.txt',
            'html_hex.txt',
            'js_hex.txt',
            'js_unicode.txt',
            'url_encode.txt'
            # 'XSS_auto_execute.txt'
        ]
    },
    '2': {  # SQLi
        'name': 'SQLi',
        'path': 'dataset_txt/SQLi/encode',
        'files': [
            # 'sqliv2.txt',
            # 'sqli.txt',
            # 'SQLiV3.txt',
            'base64encode.txt',
            'decentities.txt',
            'hexentities.txt',
            'charencode.txt',
            'charunicodeencode.txt',
            'chardoubleencode.txt'
            # 'sqlite_poc.txt'
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
    Returns dict with bypassed and blocked payloads, plus timing metrics.
    """
    filename = os.path.basename(file_path)
    print(f"\n{'='*80}")
    print(f"Testing File: {filename}")
    print(f"{'='*80}")
    
    results = {
        'bypassed': [],
        'blocked': [],
        'executed': [],  # Payloads that were confirmed executed
        'response_times': [],  # All response times in milliseconds
        'bypassed_times': [],  # Response times for bypassed requests
        'blocked_times': [],   # Response times for blocked requests
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
                    # Start timing
                    start_time = time.perf_counter()
                    
                    if attack_type == 'XSS':
                        # POST payload to blog endpoint for XSS
                        xss_data = {'text': payload}
                        headers = {'Referer': POSTS_URL}
                        
                        r = session.post(POSTS_URL, data=xss_data, headers=headers, 
                                       timeout=10, allow_redirects=False)
                        status = r.status_code
                        response_text = r.text
                        
                        # End timing
                        end_time = time.perf_counter()
                        response_time_ms = (end_time - start_time) * 1000
                        results['response_times'].append(response_time_ms)
                        
                        # Check if blocked by WAF (403 + "Forbidden" in response)
                        if status == 403 and "Forbidden" in response_text:
                            results['blocked'].append(payload)
                            results['blocked_times'].append(response_time_ms)
                        else:
                            # WAF bypassed - check response headers for execution status
                            xss_stored = r.headers.get('X-XSS-Stored', 'false')
                            xss_success = r.headers.get('X-XSS-Success', 'false')
                            post_id = r.headers.get('X-Post-ID', '')
                            
                            if status == 302 and xss_stored == 'true':
                                results['bypassed'].append(payload)
                                results['bypassed_times'].append(response_time_ms)
                                
                                # Check if server confirmed payload will execute
                                if xss_success == 'true':
                                    results['executed'].append(payload)
                                    print(f"  [✓] XSS EXECUTED [{i}] (ID:{post_id}, {response_time_ms:.2f}ms): {payload[:70]}...")
                                else:
                                    print(f"  [~] XSS STORED (not executable) [{i}]: {payload[:70]}...")
                            elif status == 302:
                                # Stored but headers missing
                                results['bypassed'].append(payload)
                                results['bypassed_times'].append(response_time_ms)
                                results['executed'].append(payload)  # Assume executed if no headers
                                print(f"  [?] XSS STORED (no headers) [{i}] ({response_time_ms:.2f}ms): {payload[:70]}...")
                            else:
                                results['bypassed'].append(payload)
                                results['bypassed_times'].append(response_time_ms)
                                print(f"  [~] BYPASSED (status={status}) [{i}]: {payload[:70]}...")
                    
                    elif attack_type == 'SQLi':
                        # POST payload to login endpoint for SQLi
                        sqli_data = {'username': payload, 'password': 'anything'}
                        
                        r = session.post(LOGIN_URL, data=sqli_data, 
                                       timeout=10, allow_redirects=False)
                        status = r.status_code
                        response_text = r.text
                        
                        # End timing
                        end_time = time.perf_counter()
                        response_time_ms = (end_time - start_time) * 1000
                        results['response_times'].append(response_time_ms)
                        
                        # Check if blocked by WAF
                        if status == 403 and "Forbidden" in response_text:
                            results['blocked'].append(payload)
                            results['blocked_times'].append(response_time_ms)
                        else:
                            results['bypassed'].append(payload)
                            results['bypassed_times'].append(response_time_ms)
                            
                            # Check if SQLi succeeded (login bypassed or got data)
                            sqli_success = r.headers.get('X-SQLi-Success', 'false')
                            rows_returned = r.headers.get('X-Rows-Returned', '0')
                            bypassed_user = r.headers.get('X-Bypassed-User', '')
                            
                            if sqli_success == 'true':
                                results['executed'].append(payload)
                                print(f"  [✓] SQLi SUCCESS [{i}] (User: {bypassed_user}): {payload[:80]}...")
                            elif sqli_success == 'partial':
                                results['executed'].append(payload)
                                print(f"  [✓] SQLi DATA [{i}] (Rows: {rows_returned}): {payload[:80]}...")
                            else:
                                print(f"  [~] BYPASSED (no exec) [{i}]: {payload[:80]}...")
                    
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

def save_bypassed_payloads(output_folder, filename, bypassed_payloads, stats, executed_payloads=None):
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
            f.write(f"Bypassed (WAF): {stats['bypassed_count']}\n")
            f.write(f"Blocked (WAF): {stats['blocked_count']}\n")
            f.write(f"Bypass Rate: {stats['bypass_rate']:.2f}%\n")
            
            # Add executed payloads stats
            executed_count = stats.get('executed_count', 0)
            if executed_count > 0:
                execution_rate = (executed_count / stats['total_count'] * 100) if stats['total_count'] > 0 else 0
                f.write(f"\n>>> EXECUTED (Confirmed Success): {executed_count}\n")
                f.write(f">>> Execution Rate: {execution_rate:.2f}%\n")
            
            f.write("="*80 + "\n\n")
            
            # Write EXECUTED payloads first (most important)
            if executed_payloads:
                f.write("EXECUTED PAYLOADS (Payload will trigger on server):\n")
                f.write("-"*80 + "\n")
                for payload in executed_payloads:
                    f.write(payload + '\n')
                f.write("\n")
            
            # Write all bypassed payloads
            f.write("ALL BYPASSED PAYLOADS:\n")
            f.write("-"*80 + "\n")
            for payload in bypassed_payloads:
                f.write(payload + '\n')
        
        executed_msg = f" ({executed_count} executed)" if executed_count > 0 else ""
        print(f"[+] Saved {len(bypassed_payloads)} bypassed payloads{executed_msg} to: {output_path}")
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
    
    # Determine target URL based on attack type
    target_url = LOGIN_URL if config['name'] == 'SQLi' else POSTS_URL
    
    # Record test start time
    test_start_time = datetime.now()
    
    print(f"\n{'='*80}")
    print(f"PAYLOAD TESTING - {config['name']} Attack")
    print(f"{'='*80}")
    print(f"Target URL: {target_url}")
    print(f"Encode Folder: {config['path']}")
    print(f"Output Folder: {output_folder}")
    print(f"Credentials: {USERNAME}:{PASSWORD}")
    print(f"Total Files: {len(config['files'])}")
    print(f"Start Time: {test_start_time.isoformat()}")
    print(f"{'='*80}\n")
    
    # Authenticate once for all tests
    session = login_and_get_session()
    
    if not session:
        print("[-] Authentication failed. Aborting test.")
        return
    
    overall_results = {
        'total_bypassed': 0,
        'total_blocked': 0,
        'total_executed': 0,
        'total_tested': 0,
        'files_processed': 0
    }
    
    # Collect all timing data
    all_response_times = []
    all_bypassed_times = []
    all_blocked_times = []
    
    # Test each file
    for file_name in config['files']:
        file_path = os.path.join(config['path'], file_name)
        
        if not os.path.exists(file_path):
            print(f"[-] Warning: File not found: {file_path}")
            continue
        
        # Test the file
        results = test_single_file(session, file_path, config['name'])
        
        # Collect timing data
        all_response_times.extend(results.get('response_times', []))
        all_bypassed_times.extend(results.get('bypassed_times', []))
        all_blocked_times.extend(results.get('blocked_times', []))
        
        # Update overall statistics
        bypassed_count = len(results['bypassed'])
        blocked_count = len(results['blocked'])
        executed_count = len(results.get('executed', []))
        total_count = bypassed_count + blocked_count
        
        overall_results['total_bypassed'] += bypassed_count
        overall_results['total_blocked'] += blocked_count
        overall_results['total_executed'] += executed_count
        overall_results['total_tested'] += total_count
        overall_results['files_processed'] += 1
        
        # Print file summary
        bypass_rate = (bypassed_count / total_count * 100) if total_count > 0 else 0
        execution_rate = (executed_count / total_count * 100) if total_count > 0 else 0
        print(f"\n{'='*80}")
        print(f"File: {file_name} - Summary")
        print(f"{'='*80}")
        print(f"Total Tested: {total_count}")
        print(f"Bypassed (WAF): {bypassed_count}")
        print(f"Blocked (WAF): {blocked_count}")
        print(f"Bypass Rate: {bypass_rate:.2f}%")
        if executed_count > 0:
            print(f">>> EXECUTED (Confirmed): {executed_count}")
            print(f">>> Execution Rate: {execution_rate:.2f}%")
        print(f"{'='*80}\n")
        
        # Prepare statistics for saving
        stats = {
            'total_count': total_count,
            'bypassed_count': bypassed_count,
            'blocked_count': blocked_count,
            'executed_count': executed_count,
            'bypass_rate': bypass_rate,
            'execution_rate': execution_rate
        }
        
        # Save bypassed payloads to output folder with statistics
        if results['bypassed']:
            save_bypassed_payloads(
                output_folder, file_name, results['bypassed'], stats,
                executed_payloads=results.get('executed', [])
            )
        else:
            print(f"[*] No bypassed payloads for {file_name}")
    
    # Record test end time
    test_end_time = datetime.now()
    total_test_duration = (test_end_time - test_start_time).total_seconds()
    
    # Calculate timing statistics
    timing_stats = calculate_timing_stats(all_response_times, all_bypassed_times, all_blocked_times)
    
    # Print overall summary
    overall_bypass_rate = (overall_results['total_bypassed'] / overall_results['total_tested'] * 100) if overall_results['total_tested'] > 0 else 0
    overall_execution_rate = (overall_results['total_executed'] / overall_results['total_tested'] * 100) if overall_results['total_tested'] > 0 else 0
    
    print("\n" + "="*80)
    print(f"OVERALL TEST RESULTS - {config['name']} Attack")
    print("="*80)
    print(f"Files Processed: {overall_results['files_processed']}/{len(config['files'])}")
    print(f"Total Payloads Tested: {overall_results['total_tested']}")
    print(f"Total Bypassed (WAF): {overall_results['total_bypassed']}")
    print(f"Total Blocked (WAF): {overall_results['total_blocked']}")
    print(f"Overall Bypass Rate: {overall_bypass_rate:.2f}%")
    if overall_results['total_executed'] > 0:
        print(f"\n>>> TOTAL EXECUTED (Confirmed Successful): {overall_results['total_executed']}")
        print(f">>> Overall Execution Rate: {overall_execution_rate:.2f}%")
    
    # Print timing metrics
    print("\n" + "-"*80)
    print("TIMING METRICS (for WAF performance comparison)")
    print("-"*80)
    print(f"Total Test Duration: {total_test_duration:.2f} seconds")
    print(f"Throughput: {overall_results['total_tested'] / total_test_duration:.2f} requests/second")
    print(f"\nAll Requests:")
    print(f"  Mean Response Time: {timing_stats['all']['mean']:.2f} ms")
    print(f"  Median Response Time: {timing_stats['all']['median']:.2f} ms")
    print(f"  Std Dev: {timing_stats['all']['std_dev']:.2f} ms")
    print(f"  Min: {timing_stats['all']['min']:.2f} ms | Max: {timing_stats['all']['max']:.2f} ms")
    print(f"  P50: {timing_stats['all']['p50']:.2f} ms | P90: {timing_stats['all']['p90']:.2f} ms | P99: {timing_stats['all']['p99']:.2f} ms")
    
    if timing_stats['blocked']['count'] > 0:
        print(f"\nBlocked Requests (WAF triggered):")
        print(f"  Count: {timing_stats['blocked']['count']}")
        print(f"  Mean Response Time: {timing_stats['blocked']['mean']:.2f} ms")
        print(f"  Median Response Time: {timing_stats['blocked']['median']:.2f} ms")
        print(f"  P90: {timing_stats['blocked']['p90']:.2f} ms | P99: {timing_stats['blocked']['p99']:.2f} ms")
    
    if timing_stats['bypassed']['count'] > 0:
        print(f"\nBypassed Requests (WAF allowed):")
        print(f"  Count: {timing_stats['bypassed']['count']}")
        print(f"  Mean Response Time: {timing_stats['bypassed']['mean']:.2f} ms")
        print(f"  Median Response Time: {timing_stats['bypassed']['median']:.2f} ms")
        print(f"  P90: {timing_stats['bypassed']['p90']:.2f} ms | P99: {timing_stats['bypassed']['p99']:.2f} ms")
    
    print("="*80)
    
    # Save metrics to JSON file for comparison
    # Determine which WAF is being tested based on BASE_URL
    waf_type = 'modsecurity' if '8080' in BASE_URL else 'uniembed'
    waf_name = TARGET_CONFIGS.get(waf_type, {}).get('name', 'Unknown')
    
    metrics_report = {
        'test_info': {
            'waf_type': waf_type,
            'waf_name': waf_name,
            'attack_type': config['name'],
            'target_url': target_url,
            'start_time': test_start_time.isoformat(),
            'end_time': test_end_time.isoformat(),
            'total_duration_seconds': total_test_duration
        },
        'results': {
            'total_tested': overall_results['total_tested'],
            'total_bypassed': overall_results['total_bypassed'],
            'total_blocked': overall_results['total_blocked'],
            'total_executed': overall_results['total_executed'],
            'bypass_rate_percent': overall_bypass_rate,
            'execution_rate_percent': overall_execution_rate
        },
        'performance_metrics': {
            'throughput_rps': overall_results['total_tested'] / total_test_duration if total_test_duration > 0 else 0,
            'all_requests': timing_stats['all'],
            'blocked_requests': timing_stats['blocked'],
            'bypassed_requests': timing_stats['bypassed']
        }
    }
    
    # Save JSON metrics
    os.makedirs(output_folder, exist_ok=True)
    metrics_file = os.path.join(output_folder, 'metrics_report.json')
    with open(metrics_file, 'w', encoding='utf-8') as f:
        json.dump(metrics_report, f, indent=2)
    print(f"\n[+] Saved performance metrics to: {metrics_file}")


def calculate_timing_stats(all_times, bypassed_times, blocked_times):
    """Calculate timing statistics for performance comparison."""
    def calc_stats(times):
        if not times:
            return {
                'count': 0, 'mean': 0, 'median': 0, 'std_dev': 0,
                'min': 0, 'max': 0, 'p50': 0, 'p90': 0, 'p99': 0
            }
        
        sorted_times = sorted(times)
        n = len(sorted_times)
        
        return {
            'count': n,
            'mean': statistics.mean(times),
            'median': statistics.median(times),
            'std_dev': statistics.stdev(times) if n > 1 else 0,
            'min': min(times),
            'max': max(times),
            'p50': sorted_times[int(n * 0.50)] if n > 0 else 0,
            'p90': sorted_times[int(n * 0.90)] if n > 0 else 0,
            'p99': sorted_times[min(int(n * 0.99), n-1)] if n > 0 else 0
        }
    
    return {
        'all': calc_stats(all_times),
        'bypassed': calc_stats(bypassed_times),
        'blocked': calc_stats(blocked_times)
    }

def main():
    parser = argparse.ArgumentParser(
        description="Payload Testing Tool for XSS/SQLi Attacks",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  # Test XSS payloads against UniEmbed WAF (default)
  python attack.py 1 xss_uniembed
  python attack.py 2 sqli_uniembed
  
  # Test payloads against ModSecurity CRS
  python attack.py 1 xss_modsecurity --target modsecurity
  python attack.py 2 sqli_modsecurity --target modsecurity
  
  # Compare both WAFs:
  # 1. Start Flask app with UNIEMBED_WAF_ENABLED=True, run tests with --target uniembed
  # 2. Start Flask app with UNIEMBED_WAF_ENABLED=False + docker-compose up, run tests with --target modsecurity
        """
    )
    
    parser.add_argument('attack_type', 
                        choices=['1', '2'],
                        help="Attack type: 1 = XSS, 2 = SQLi")
    
    parser.add_argument('output_folder',
                        help="Output folder to save bypassed payloads")
    
    parser.add_argument('--target', '-t',
                        choices=list(TARGET_CONFIGS.keys()),
                        default=DEFAULT_TARGET,
                        help=f"Target WAF: {', '.join(TARGET_CONFIGS.keys())} (default: {DEFAULT_TARGET})")
    
    args = parser.parse_args()
    
    # Set target WAF
    if not set_target(args.target):
        return
    
    run_payload_tests(args.attack_type, args.output_folder)
    
    print("\n" + "="*80)
    print("TEST EXECUTION COMPLETED")
    print("="*80)

if __name__ == "__main__":
    main()
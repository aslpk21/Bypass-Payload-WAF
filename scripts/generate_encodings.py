import os
import urllib.parse
import base64
import html

def encode_base64(payload):
    return base64.b64encode(payload.encode('utf-8')).decode('utf-8')

def encode_url(payload):
    return urllib.parse.quote(payload, safe='')

def encode_double_url(payload):
    return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')

def encode_html_decimal(payload):
    return ''.join(f'&#{ord(char)};' for char in payload)

def encode_html_hex(payload):
    return ''.join(f'&#x{ord(char):x};' for char in payload)

def encode_js_hex(payload):
    return ''.join(f'\\x{ord(char):02x}' for char in payload)

def encode_js_unicode(payload):
    return ''.join(f'\\u{ord(char):04x}' for char in payload)

def main():
    input_file = r'dataset_txt\XSS\XSS_auto_execute.txt'
    output_dir = r'dataset_txt\XSS\encode2'

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    encoding_functions = {
        'base64.txt': encode_base64,
        'url_encode.txt': encode_url,
        'double_url_encode.txt': encode_double_url,
        'html_decimal.txt': encode_html_decimal,
        'html_hex.txt': encode_html_hex,
        'js_hex.txt': encode_js_hex,
        'js_unicode.txt': encode_js_unicode
    }

    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            payloads = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
        return

    for filename, func in encoding_functions.items():
        output_path = os.path.join(output_dir, filename)
        print(f"Generating {filename}...")
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                for payload in payloads:
                    encoded_payload = func(payload)
                    f.write(encoded_payload + '\n')
            print(f"Successfully wrote to {output_path}")
        except Exception as e:
            print(f"Error writing to {output_path}: {e}")

if __name__ == '__main__':
    main()

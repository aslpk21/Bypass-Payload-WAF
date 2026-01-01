# -*- coding: utf-8 -*-
"""
Script để lọc payload XSS tự động thực thi (không cần user interaction)
"""

import re

# Đường dẫn file
INPUT_FILE = r"c:\TIU\NT213\Project\dataset_txt\XSS\XSS.txt"
OUTPUT_FILE = r"c:\TIU\NT213\Project\dataset_txt\XSS\XSS_auto_execute.txt"

# Các pattern cho payload tự động thực thi
# Events tự động kích hoạt không cần user interaction:
AUTO_EVENTS = [
    # Load events
    r'onload\s*=',
    r'onerror\s*=',
    r'onreadystatechange\s*=',
    
    # Auto-focus events (với autofocus attribute)
    r'autofocus[^>]*onfocus\s*=',
    r'onfocus\s*=[^>]*autofocus',
    
    # Animation/transition events (có thể tự động nếu có CSS đi kèm)
    r'onanimationstart\s*=',
    r'onanimationend\s*=',
    r'onanimationiteration\s*=',
    r'ontransitionend\s*=',
    r'ontransitionrun\s*=',
    r'ontransitionstart\s*=',
    
    # Details element với open attribute
    r'<details[^>]*ontoggle\s*=[^>]*open',
    r'<details[^>]*open[^>]*ontoggle\s*=',
    
    # Video/audio autoplay events  
    r'autoplay[^>]*onplay\s*=',
    r'onplay\s*=[^>]*autoplay',
    r'autoplay[^>]*onplaying\s*=',
    r'onplaying\s*=[^>]*autoplay',
    r'autoplay[^>]*oncanplay\s*=',
    
    # Marquee onstart (tự động khi element render)
    r'<marquee[^>]*onstart\s*=',
    
    # SVG onbegin
    r'onbegin\s*=',
    
    # Script tag with content (tự động chạy)
    r'<script[^>]*>[^<]+</script>',
    r'<script\s*>',
    
    # Body/frameset onload
    r'<body[^>]*onload\s*=',
    r'<frameset[^>]*onload\s*=',
    
    # iframe onload
    r'<iframe[^>]*onload\s*=',
    
    # img onerror (nếu src không hợp lệ)
    r'<img[^>]*onerror\s*=',
    r'<image[^>]*onerror\s*=',
    r'<input[^>]*type\s*=\s*["\']?image[^>]*onerror\s*=',
    
    # svg onload
    r'<svg[^>]*onload\s*=',
    r'<svg[^>]*>[^<]*<[^>]+onload\s*=',  # nested elements in svg with onload
    
    # object/embed với javascript
    r'<object[^>]*data\s*=\s*["\']?javascript:',
    
    # meta refresh/redirect
    r'<meta[^>]*http-equiv\s*=\s*["\']?refresh',
    
    # CSS expressions (IE)
    r'expression\s*\(',
    
    # javascript: trong href với auto-trigger
    # (thường cần click, nhưng một số context có thể auto)
    
    # Applet onreadystatechange
    r'<applet[^>]*onreadystatechange\s*=',
    
    # Embed onfocusin với autofocus context
    r'<embed[^>]*onfocusin\s*=',
    
    # srcset với onerror
    r'srcset\s*=[^>]*onerror\s*=',
    r'onerror\s*=[^>]*srcset\s*=',
    
    # SSI (Server-Side Include) injection - tự động thực thi trên server
    r'<!--#exec',
    r'<!--#include',
    r'<!--#echo',
    r'<!--#config',
    
    # iframe với data: URI hoặc javascript:
    r'<iframe[^>]*src\s*=\s*["\']?data:',
    r'<iframe[^>]*src\s*=\s*["\']?javascript:',
    
    # object với data URI
    r'<object[^>]*data\s*=\s*["\']?data:',
    
    # embed với src
    r'<embed[^>]*src\s*=.*onerror',
    
    # link stylesheet onerror
    r'<link[^>]*onerror\s*=',
    
    # video/audio source onerror
    r'<source[^>]*onerror\s*=',
    
    # isindex onerror
    r'<isindex[^>]*onerror\s*=',
    
    # object onerror
    r'<object[^>]*onerror\s*=',
    
    # style onload
    r'<style[^>]*onload\s*=',
    
    # body onunhandledrejection (Promise rejection)
    r'onunhandledrejection\s*=',
]

# Compile patterns
AUTO_PATTERNS = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in AUTO_EVENTS]

def is_auto_execute_payload(line: str) -> bool:
    """
    Kiểm tra xem payload có phải là loại tự động thực thi không
    """
    for pattern in AUTO_PATTERNS:
        if pattern.search(line):
            return True
    return False

def main():
    # Đọc file với encoding utf-8-sig để xử lý BOM nếu có
    try:
        with open(INPUT_FILE, 'r', encoding='utf-8-sig') as f:
            lines = f.readlines()
    except UnicodeDecodeError:
        # Fallback to utf-8 nếu utf-8-sig không hoạt động
        try:
            with open(INPUT_FILE, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except UnicodeDecodeError:
            # Cuối cùng thử với latin-1 (không bao giờ fail)
            with open(INPUT_FILE, 'r', encoding='latin-1') as f:
                lines = f.readlines()
    
    print(f"Đọc được {len(lines)} dòng từ file gốc")
    
    # Lọc payload tự động thực thi
    auto_payloads = []
    for line in lines:
        line = line.rstrip('\r\n')
        if line and is_auto_execute_payload(line):
            auto_payloads.append(line)
    
    print(f"Tìm thấy {len(auto_payloads)} payload tự động thực thi")
    
    # Ghi ra file mới
    with open(OUTPUT_FILE, 'w', encoding='utf-8', newline='\n') as f:
        for payload in auto_payloads:
            f.write(payload + '\n')
    
    print(f"Đã ghi vào: {OUTPUT_FILE}")
    
    # In 10 payload đầu tiên để kiểm tra
    print("\n=== 10 payload đầu tiên ===")
    for i, p in enumerate(auto_payloads[:10], 1):
        print(f"{i}. {p[:100]}...")

if __name__ == '__main__':
    main()

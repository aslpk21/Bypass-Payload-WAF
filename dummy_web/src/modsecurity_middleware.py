
import re
import time
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ModSecurityMock")

class ModSecurityMiddleware:
    def __init__(self):
        # Compiled Regex Rules based on OWASP Core Rule Set logic
        # 1. SQL Injection Patterns
        self.sqli_patterns = [
            re.compile(r"(?i)\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE)\b.*\b(FROM|INTO|TABLE|DATABASE)\b"),
            re.compile(r"(?i)\b(OR|AND)\b\s+['\"]?(\d+|true|false)['\"]?\s*=\s*['\"]?(\d+|true|false)['\"]?"),
            re.compile(r"(?i)[\"']\s*(OR|AND)\s+[\"']?\d+[\"']?\s*=\s*[\"']?\d+"),
            re.compile(r"(?i)(--|#|\/\*).*"),  # Comments
            re.compile(r"(?i)\b(SLEEP|BENCHMARK|DELAY|WAITFOR)\b"), # Time-based
            re.compile(r"(?i)\b(@@VERSION|user\(\)|database\(\))\b"), # System variables
            re.compile(r"(?i)[\s\d]'|'[\s\d]"), # Single quote anomalies
            re.compile(r"(?i)admin'--"),
            re.compile(r"(?i)'\s*or\s*1=1")
        ]

        # 2. XSS Patterns
        self.xss_patterns = [
            re.compile(r"(?i)<script.*?>.*?</script>"),
            re.compile(r"(?i)javascript:"),
            re.compile(r"(?i)on\w+\s*="), # Event handlers like onload=, onerror=
            re.compile(r"(?i)<(iframe|frame|object|embed|applet|meta|img|svg|body|html)[^>]*>"),
            re.compile(r"(?i)alert\s*\("),
            re.compile(r"(?i)document\.cookie"),
            re.compile(r"(?i)eval\s*\(")
        ]
        
    def check_request(self, request_data):
        """
        Inspects request data (args and form) against rules.
        Returns (is_blocked, matched_pattern, duration_ms)
        """
        start_time = time.perf_counter()
        
        # Combine all values to check
        values_to_check = []
        
        if hasattr(request_data, 'args'):
            values_to_check.extend(request_data.args.values())
            
        if hasattr(request_data, 'form'):
            values_to_check.extend(request_data.form.values())
            
        is_blocked = False
        matched_rule = None
        
        for value in values_to_check:
            if not isinstance(value, str):
                continue
                
            # Check SQLi
            for pattern in self.sqli_patterns:
                if pattern.search(value):
                    is_blocked = True
                    matched_rule = f"SQLi: {pattern.pattern}"
                    break
            
            if is_blocked: break
            
            # Check XSS
            for pattern in self.xss_patterns:
                if pattern.search(value):
                    is_blocked = True
                    matched_rule = f"XSS: {pattern.pattern}"
                    break
                    
            if is_blocked: break

        end_time = time.perf_counter()
        duration_ms = (end_time - start_time) * 1000
        
        return is_blocked, matched_rule, duration_ms

# Singleton instance
modsec = ModSecurityMiddleware()

def check_security(request):
    """Refactored helper for usage in before_request"""
    return modsec.check_request(request)

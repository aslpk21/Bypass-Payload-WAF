# -*- coding: utf-8 -*-
"""
Decoding Middleware for Encoded Payload Execution Evaluation

This middleware decodes various encoded payloads AFTER WAF check,
allowing evaluation of whether WAF can detect encoded attack payloads.

Supported encodings:
- Base64
- URL Encoding (single and double)
- HTML Entities (decimal and hex)
- Unicode escapes
- JavaScript hex/unicode
"""

import base64
import html
import re
import urllib.parse
from functools import wraps
from flask import request, g
import os

# Configuration
DECODE_ENABLED = os.getenv('DECODE_PAYLOADS', 'True') == 'True'


def decode_base64(text):
    """Decode base64 encoded strings."""
    try:
        # Check if it looks like base64 (only valid base64 chars)
        if re.match(r'^[A-Za-z0-9+/=]+$', text) and len(text) >= 4:
            # Try to decode
            decoded = base64.b64decode(text).decode('utf-8', errors='ignore')
            # Only return if it contains printable characters
            if decoded and all(c.isprintable() or c.isspace() for c in decoded):
                return decoded
    except:
        pass
    return text


def decode_url(text, double=False):
    """Decode URL encoded strings."""
    try:
        decoded = urllib.parse.unquote(text)
        if double:
            decoded = urllib.parse.unquote(decoded)
        return decoded
    except:
        return text


def decode_html_entities(text):
    """Decode HTML entities (decimal and hex)."""
    try:
        return html.unescape(text)
    except:
        return text


def decode_unicode_escapes(text):
    """Decode unicode escape sequences like \\uXXXX or \\xXX."""
    try:
        # Handle \\uXXXX
        def replace_unicode(m):
            try:
                return chr(int(m.group(1), 16))
            except:
                return m.group(0)
        
        text = re.sub(r'\\u([0-9a-fA-F]{4})', replace_unicode, text)
        
        # Handle \\xXX
        def replace_hex(m):
            try:
                return chr(int(m.group(1), 16))
            except:
                return m.group(0)
        
        text = re.sub(r'\\x([0-9a-fA-F]{2})', replace_hex, text)
        
        return text
    except:
        return text


def decode_js_escapes(text):
    """Decode JavaScript style escapes."""
    try:
        # Handle %uXXXX (JavaScript Unicode)
        def replace_js_unicode(m):
            try:
                return chr(int(m.group(1), 16))
            except:
                return m.group(0)
        
        text = re.sub(r'%u([0-9a-fA-F]{4})', replace_js_unicode, text)
        return text
    except:
        return text


def decode_all(text):
    """
    Apply all decoding methods to text.
    Order matters: URL decode first, then others.
    """
    if not text:
        return text
    
    original = text
    
    # 1. URL decode (handles single URL encoding)
    text = decode_url(text)
    
    # 2. Double URL decode if still has % encoding
    if '%' in text:
        text = decode_url(text, double=True)
    
    # 3. HTML entities decode
    if '&' in text:
        text = decode_html_entities(text)
    
    # 4. Unicode escapes
    if '\\u' in text or '\\x' in text:
        text = decode_unicode_escapes(text)
    
    # 5. JavaScript escapes
    if '%u' in text:
        text = decode_js_escapes(text)
    
    # 6. Base64 decode (only if text is purely base64-like)
    if text == original and re.match(r'^[A-Za-z0-9+/=]+$', text):
        text = decode_base64(text)
    
    return text


def apply_decoding_to_request():
    """
    Apply decoding to all form data in the current request.
    Stores decoded values in g.decoded_form for use by handlers.
    """
    if not DECODE_ENABLED:
        return
    
    g.decoded_form = {}
    g.original_form = {}
    
    if request.form:
        for key, value in request.form.items():
            g.original_form[key] = value
            g.decoded_form[key] = decode_all(value)
            
            # Log if decoding changed the value
            if g.decoded_form[key] != value:
                print(f"[DECODE] {key}: '{value[:50]}...' -> '{g.decoded_form[key][:50]}...'")


def get_decoded_form_value(key, default=''):
    """Get decoded form value, falling back to original if decode not enabled."""
    if hasattr(g, 'decoded_form') and key in g.decoded_form:
        return g.decoded_form[key]
    return request.form.get(key, default)


# Decorator for routes that need decoded input
def decode_input(f):
    """Decorator to apply decoding before route handler."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        apply_decoding_to_request()
        return f(*args, **kwargs)
    return decorated_function

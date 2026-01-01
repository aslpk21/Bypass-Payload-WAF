import sqlite3
import re
from flask import Blueprint, render_template, redirect, request, g, make_response

import libposts
import libuser
from uniembed_waf import waf_protect

mod_posts = Blueprint('mod_posts', __name__, template_folder='templates')


def is_executable_xss(text):
    """
    Check if the payload contains executable XSS when rendered as HTML.
    Returns True if the payload would execute JavaScript.
    Based on patterns seen in the XSS malicious dataset.
    """
    # These patterns will execute JS when rendered in HTML without sanitization
    executable_patterns = [
        # Script tags
        r'<script[^>]*>',
        r'<script',
        
        # Event handlers (any on* attribute)
        r'\bon\w+\s*=',
        
        # javascript: protocol
        r'javascript\s*:',
        
        # SVG with events
        r'<svg[^>]*on\w+',
        r'<svg[^>]*>.*?<animate[^>]*onbegin',
        
        # IMG/Image with onerror
        r'<img[^>]*onerror',
        r'<image[^>]*onerror',
        
        # Iframe with JS
        r'<iframe[^>]*src\s*=\s*["\']?javascript:',
        r'<iframe[^>]*onload',
        
        # Body/HTML with events
        r'<body[^>]*on\w+',
        r'<html[^>]*on\w+',
        
        # Input/textarea/select with autofocus + onfocus
        r'autofocus[^>]*onfocus',
        r'onfocus[^>]*autofocus',
        
        # Object/embed with JS
        r'<object[^>]*data\s*=\s*["\']?javascript:',
        r'<embed[^>]*src\s*=\s*["\']?javascript:',
        
        # Details with ontoggle
        r'<details[^>]*ontoggle',
        
        # Marquee
        r'<marquee[^>]*on\w+',
        
        # Expression (IE)
        r'expression\s*\(',
        
        # Encoded javascript
        r'j\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t\s*:',  # spaced
        r'&#\d+;.*javascript',  # HTML entity encoding
        r'&#x[0-9a-f]+;.*javascript',  # Hex entity encoding
    ]
    
    for pattern in executable_patterns:
        if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
            return True
    
    return False


@mod_posts.route('/')
@mod_posts.route('/<username>')
def do_view(username=None):

    if not username:
        if 'username' in g.session:
            username = g.session['username']

    posts = libposts.get_posts(username)
    users = libuser.userlist()

    return render_template('posts.view.html', posts=posts, username=username, users=users)


@mod_posts.route('/', methods=['POST'])
@waf_protect()
def do_create():

    if 'username' not in g.session:
        return redirect('/user/login')

    if request.method == 'POST':

        username = g.session['username']
        text_original = request.form.get('text', '')
        
        # Decode the payload AFTER WAF check for execution evaluation
        from decode_middleware import decode_all, DECODE_ENABLED
        if DECODE_ENABLED:
            text = decode_all(text_original)
            if text != text_original:
                print(f"[DECODE] XSS payload: '{text_original[:50]}...' -> '{text[:50]}...'")
        else:
            text = text_original

        # Store the post (vulnerable - no sanitization)
        post_id = libposts.post(username, text)

        # Check if payload is executable XSS
        is_executable = is_executable_xss(text)

        # Create response with simple XSS indicators
        response = make_response(redirect('/'))
        
        if post_id:
            response.headers['X-Post-ID'] = str(post_id)
            response.headers['X-XSS-Stored'] = 'true'
            
            # Key indicator: XSS will execute when page is rendered
            if is_executable:
                response.headers['X-XSS-Success'] = 'true'
            else:
                response.headers['X-XSS-Success'] = 'false'
        else:
            response.headers['X-XSS-Stored'] = 'false'
            response.headers['X-XSS-Success'] = 'false'

        return response

    return redirect('/')


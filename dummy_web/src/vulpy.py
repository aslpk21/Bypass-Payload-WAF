#!/usr/bin/env python3

from pathlib import Path

from flask import Flask, g, redirect, request

import libsession
from mod_api import mod_api
from mod_csp import mod_csp
from mod_hello import mod_hello
from mod_mfa import mod_mfa
from mod_posts import mod_posts
from mod_user import mod_user
from dotenv import load_dotenv
import os

from uniembed_waf import initialize_waf, UNIEMBED_WAF_ENABLED

# load_dotenv()

app = Flask('vulpy')
app.config['SECRET_KEY'] = 'aaaaaaa'

app.register_blueprint(mod_hello, url_prefix='/hello')
app.register_blueprint(mod_user, url_prefix='/user')
app.register_blueprint(mod_posts, url_prefix='/posts')
app.register_blueprint(mod_mfa, url_prefix='/mfa')
app.register_blueprint(mod_csp, url_prefix='/csp')
app.register_blueprint(mod_api, url_prefix='/api')

csp_file = Path('csp.txt')
csp = ''

if csp_file.is_file():
    with csp_file.open() as f:
        for line in f.readlines():
            if line.startswith('#'):
                continue
            line = line.replace('\n', '')
            if line:
                csp += line
if csp:
    print('CSP:', csp)


@app.route('/')
def do_home():
    return redirect('/posts')

@app.before_request
def before_request():
    g.session = libsession.load(request)

@app.after_request
def add_csp_headers(response):
    if csp:
        response.headers['Content-Security-Policy'] = csp
    return response

W2V_PATH = "C:/TIU/NT213/Project/embeddings/GoogleNews-vectors-negative300.bin.gz"
FT_PATH = "C:/TIU/NT213/Project/embeddings/cc.en.300.bin"

initialize_waf(W2V_PATH, FT_PATH)

app.run(debug=False, host='0.0.0.0', port=5000, extra_files='csp.txt')

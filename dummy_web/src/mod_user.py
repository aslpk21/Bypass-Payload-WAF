from flask import Blueprint, render_template, redirect, request, g, session, make_response, flash
import libmfa
import libuser
import libsession
from uniembed_waf import waf_protect

mod_user = Blueprint('mod_user', __name__, template_folder='templates')


import logging
import time

@mod_user.route('/login', methods=['GET', 'POST'])
@waf_protect(fields=["username", "password"])
def do_login():
    session.pop('username', None)

    if request.method == 'POST':
        username_original = request.form.get('username', '')
        password_original = request.form.get('password', '')
        otp = request.form.get('otp', '')
        
        # Decode the payload AFTER WAF check for execution evaluation
        from decode_middleware import decode_all, DECODE_ENABLED
        if DECODE_ENABLED:
            username = decode_all(username_original)
            password = decode_all(password_original)
            if username != username_original:
                print(f"[DECODE] SQLi username: '{username_original[:50]}...' -> '{username[:50]}...'")
            if password != password_original:
                print(f"[DECODE] SQLi password: '{password_original[:30]}...' -> '{password[:30]}...'")
        else:
            username = username_original
            password = password_original

        login_result = None
        
        try:
            # Attempt login - returns LoginResult object
            login_result = libuser.login(username, password)
                
        except Exception as e:
            flash("System error occurred")
            response = make_response(render_template('user.login.mfa.html'), 500)
            response.headers['X-SQLi-Success'] = 'false'
            response.headers['X-Rows-Returned'] = '0'
            return response

        # Simple SQLi indicator function
        def add_sqli_headers(resp):
            if login_result:
                resp.headers['X-Rows-Returned'] = str(login_result.rows_returned)
                # SQLi Success = login succeeded (bypass) OR rows returned > 0
                if login_result.success:
                    resp.headers['X-SQLi-Success'] = 'true'
                    resp.headers['X-Bypassed-User'] = str(login_result.username)
                elif login_result.rows_returned > 0:
                    resp.headers['X-SQLi-Success'] = 'partial'  # Got data but no login
                else:
                    resp.headers['X-SQLi-Success'] = 'false'
            return resp
        
        if not login_result or not login_result.success:
            flash("Invalid user or password")
            response = make_response(render_template('user.login.mfa.html'), 401)
            return add_sqli_headers(response)

        # MFA check
        if libmfa.mfa_is_enabled(str(login_result)):
            if not otp:
                flash("OTP required")
                response = make_response(render_template('user.login.mfa.html'), 403)
                return add_sqli_headers(response)
            
            if not libmfa.mfa_validate(str(login_result), otp):
                flash("Invalid OTP")
                response = make_response(render_template('user.login.mfa.html'), 403)
                return add_sqli_headers(response)

        # Success - Login bypassed!
        response = make_response(redirect('/'), 302)
        response = libsession.create(response=response, username=str(login_result))
        return add_sqli_headers(response)

    return render_template('user.login.mfa.html')


@mod_user.route('/create', methods=['GET', 'POST'])
def do_create():

    session.pop('username', None)

    if request.method == 'POST':

        username = request.form.get('username')
        password = request.form.get('password')
        #email = request.form.get('password')
        if not username or not password:
            flash("Please, complete username and password")
            return render_template('user.create.html')

        libuser.create(username, password)
        flash("User created. Please login.")
        return redirect('/user/login')

        #session['username'] = libuser.login(username, password)

        #if session['username']:
        #    return redirect('/')

    return render_template('user.create.html')


@mod_user.route('/chpasswd', methods=['GET', 'POST'])
def do_chpasswd():

    if request.method == 'POST':

        password = request.form.get('password')
        password_again = request.form.get('password_again')

        if password != password_again:
            flash("The passwords don't match")
            return render_template('user.chpasswd.html')

        if not libuser.password_complexity(password):
            flash("The password don't comply our complexity requirements")
            return render_template('user.chpasswd.html')

        libuser.password_change(g.session['username'], password) # = libuser.login(username, password)
        flash("Password changed")

    return render_template('user.chpasswd.html')


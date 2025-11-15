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
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        otp = request.form.get('otp', '')

        start_time = time.time()
        sql_executed = False
        query_result_count = 0
        
        try:
            # Attempt login
            login_result = libuser.login(username, password)
            sql_executed = True
            
            # Nếu libuser.login trả về info về query
            if hasattr(login_result, 'query_info'):
                query_result_count = login_result.query_info.get('row_count', 0)
                
        except Exception as e:
            query_time = time.time() - start_time
            flash("System error occurred")
            response = make_response(render_template('user.login.mfa.html'), 500)
            response.headers['X-Login-Status'] = 'SQL_ERROR'
            response.headers['X-Error-Type'] = type(e).__name__
            response.headers['X-Query-Time'] = f"{query_time:.4f}"
            return response

        query_time = time.time() - start_time
        
        if not login_result:
            flash("Invalid user or password")
            response = make_response(render_template('user.login.mfa.html'), 401)
            response.headers['X-Login-Status'] = 'INVALID_CREDENTIALS'
            response.headers['X-Query-Time'] = f"{query_time:.4f}"
            response.headers['X-SQL-Executed'] = 'true' if sql_executed else 'false'
            response.headers['X-Result-Count'] = str(query_result_count)
            return response

        # MFA check
        if libmfa.mfa_is_enabled(login_result):
            if not otp:
                flash("OTP required")
                response = make_response(render_template('user.login.mfa.html'), 403)
                response.headers['X-Login-Status'] = 'MFA_REQUIRED'
                response.headers['X-Query-Time'] = f"{query_time:.4f}"
                return response
            
            if not libmfa.mfa_validate(login_result, otp):
                flash("Invalid OTP")
                response = make_response(render_template('user.login.mfa.html'), 403)
                response.headers['X-Login-Status'] = 'INVALID_OTP'
                response.headers['X-Query-Time'] = f"{query_time:.4f}"
                return response

        # Success
        response = make_response(redirect('/'), 302)
        response = libsession.create(response=response, username=login_result)
        response.headers['X-Login-Status'] = 'SUCCESS'
        response.headers['X-Query-Time'] = f"{query_time:.4f}"
        return response

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


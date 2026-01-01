import sqlite3
import libuser


class LoginResult:
    """Simple class to hold login result for SQLi indicator"""
    def __init__(self, username=None, success=False, rows_returned=0):
        self.username = username
        self.success = success
        self.rows_returned = rows_returned
    
    def __bool__(self):
        return self.success
    
    def __str__(self):
        return self.username if self.username else ""


def login(username, password):

    conn = sqlite3.connect('db_users.sqlite')
    conn.set_trace_callback(print)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    # Vulnerable query (SQL Injection here)
    query = "SELECT * FROM users WHERE username = '{}' and password = '{}'".format(username, password)

    user = c.execute(query).fetchone()
    
    # Count rows returned - indicator for SQLi success
    all_users = c.execute(query).fetchall()
    rows_returned = len(all_users)

    if user:
        return LoginResult(
            username=user['username'],
            success=True,
            rows_returned=rows_returned
        )
    else:
        return LoginResult(
            username=None,
            success=False,
            rows_returned=rows_returned
        )


def create(username, password):

    conn = sqlite3.connect('db_users.sqlite')
    c = conn.cursor()

    c.execute("INSERT INTO users (username, password, failures, mfa_enabled, mfa_secret) VALUES ('%s', '%s', '%d', '%d', '%s')" %(username, password, 0, 0, ''))

    conn.commit()
    conn.close()


def userlist():

    conn = sqlite3.connect('db_users.sqlite')
    conn.set_trace_callback(print)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    users = c.execute("SELECT * FROM users").fetchall()

    if not users:
        return []
    else:
        return [ user['username'] for user in users ]


def password_change(username, password):

    conn = sqlite3.connect('db_users.sqlite')
    conn.set_trace_callback(print)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute("UPDATE users SET password = '{}' WHERE username = '{}'".format(password, username))
    conn.commit()

    return True


def password_complexity(password):
    return True


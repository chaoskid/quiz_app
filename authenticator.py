from functools import wraps
from flask import session, redirect, url_for
from routes import *

#Adding custom decorator for user logged in.
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_logged_in' not in session and 'admin_logged_in' not in session:
            return redirect(url_for('routes.login'))  # Redirect to login if no user or admin session
        return f(*args, **kwargs)
    return decorated_function

#Adding custom decorator for admin logged in.
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session:
            return redirect(url_for('routes.login'))  # Redirect to login if no user or admin session
        return f(*args, **kwargs)
    return decorated_function
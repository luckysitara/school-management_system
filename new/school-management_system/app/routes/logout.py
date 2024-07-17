from flask import Blueprint, redirect, url_for
from flask_login import logout_user

logout_bp = Blueprint('logout', __name__)

@logout_bp.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('main.index'))

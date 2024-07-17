from flask import Blueprint, render_template, redirect, url_for, flash
from app import db, bcrypt
from app.forms import RegistrationForm
from app.models import User

signup_bp = Blueprint('signup', __name__)

@signup_bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in.', 'success')
        return redirect(url_for('login.login'))
    return render_template('register.html', form=form)

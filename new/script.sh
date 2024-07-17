#!/bin/bash

# Create project directory and navigate into it
mkdir school-management_system
cd school-management_system

# Create app directory structure
mkdir -p app/routes app/templates app/static

# Create app initialization file
touch app/__init__.py

# Create models and forms files
touch app/models.py
touch app/forms.py

# Create routes files
touch app/routes/__init__.py
touch app/routes/login.py
touch app/routes/logout.py
touch app/routes/signup.py

# Create templates files
mkdir -p app/templates
touch app/templates/base.html
touch app/templates/index.html
touch app/templates/login.html
touch app/templates/register.html

# Create config file
touch config.py

# Create requirements file
touch requirements.txt

# Create run file
touch run.py

# Populate files with basic content (optional)
cat << EOF > app/__init__.py
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt

# Initialize Flask extensions
db = SQLAlchemy()
login_manager = LoginManager()
bcrypt = Bcrypt()

def create_app(config_class):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    bcrypt.init_app(app)

    # Import and register blueprints
    from app.routes.login import login_bp
    from app.routes.logout import logout_bp
    from app.routes.signup import signup_bp

    app.register_blueprint(login_bp)
    app.register_blueprint(logout_bp)
    app.register_blueprint(signup_bp)

    return app
EOF

cat << EOF > app/routes/login.py
from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_user, current_user
from app import db, bcrypt
from app.forms import LoginForm
from app.models import User

login_bp = Blueprint('login', __name__)

@login_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('main.index'))
        else:
            flash('Login unsuccessful. Please check username and password.', 'danger')
    return render_template('login.html', form=form)
EOF

cat << EOF > app/routes/logout.py
from flask import Blueprint, redirect, url_for
from flask_login import logout_user

logout_bp = Blueprint('logout', __name__)

@logout_bp.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('main.index'))
EOF

cat << EOF > app/routes/signup.py
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
EOF

cat << EOF > app/forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')
EOF

cat << EOF > app/models.py
from app import db, login_manager
from flask_login import UserMixin

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

# Callback to reload user object from the user ID stored in the session
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
EOF

cat << EOF > app/templates/base.html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{% block title %}{% endblock %}</title>
    <!-- CSS links, Bootstrap, etc. -->
</head>
<body>
    <nav>
        <ul>
            <li><a href="{{ url_for('main.index') }}">Home</a></li>
            <li><a href="{{ url_for('login.login') }}">Login</a></li>
            <li><a href="{{ url_for('signup.register') }}">Signup</a></li>
            <!-- Additional navigation links -->
        </ul>
    </nav>
    <div class="content">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">
                        {{ message }}
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        {% block content %}{% endblock %}
    </div>
    <!-- Scripts, jQuery, Bootstrap JS, etc. -->
</body>
</html>
EOF

cat << EOF > app/templates/index.html
{% extends 'base.html' %}

{% block title %}Home{% endblock %}

{% block content %}
    <h1>Welcome to the School Management System</h1>
    <!-- Home page content -->
{% endblock %}
EOF

cat << EOF > app/templates/login.html
{% extends 'base.html' %}

{% block title %}Login{% endblock %}

{% block content %}
    <h2>Login</h2>
    <form method="POST" action="">
        {{ form.hidden_tag() }}
        <p>
            {{ form.username.label }}<br>
            {{ form.username(class="form-control") }}<br>
            {% for error in form.username.errors %}
                <span style="color: red;">[{{ error }}]</span><br>
            {% endfor %}
        </p>
        <p>
            {{ form.password.label }}<br>
            {{ form.password(class="form-control") }}<br>
            {% for error in form.password.errors %}
                <span style="color: red;">[{{ error }}]</span><br>
            {% endfor %}
        </p>
        <p>{{ form.remember }} {{ form.remember.label }}</p>
        <p>{{ form.submit(class="btn btn-primary") }}</p>
    </form>
{% endblock %}
EOF

cat << EOF > app/templates/register.html
{% extends 'base.html' %}

{% block title %}Register{% endblock %}

{% block content %}
    <h2>Register</h2>
    <form method="POST" action="">
        {{ form.hidden_tag() }}
        <p>
            {{ form.username.label }}<br>
            {{ form.username(class="form-control") }}<br>
            {% for error in form.username.errors %}
                <span style="color: red;">[{{ error }}]</span><br>
            {% endfor %}
        </p>
        <p>
            {{ form.email.label }}<br>
            {{ form.email(class="form-control") }}<br>
            {% for error in form.email.errors %}
                <span style="color: red;">[{{ error }}]</span><br>
            {% endfor %}
        </p>
        <p>
            {{ form.password.label }}<br>
            {{ form.password(class="form-control") }}<br>
            {% for error in form.password.errors %}
                <span style="color: red;">[{{ error }}]</span><br>
            {% endfor %}
        </p>
        <p>
            {{ form.confirm_password.label }}<br>
            {{ form.confirm_password(class="form-control") }}<br>
            {% for error in form.confirm_password.errors %}
                <span style="color: red;">[{{ error }}]</span><br>
            {% endfor %}
        </p>
        <p>{{ form.submit(class="btn btn-primary") }}</p>
    </form>
{% endblock %}
EOF

cat << EOF > config.py
class Config:
    SECRET_KEY = 'your_secret_key_here'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///school.db'  # SQLite example, replace with your DB URI
    SQLALCHEMY_TRACK_MODIFICATIONS = False
EOF

cat << EOF > requirements.txt
Flask==2.0.1
Flask-WTF==1.0.0
Flask-SQLAlchemy==3.0.0
Flask-Login==0.5.0
Flask-Bcrypt==0.7.1
EOF

cat << EOF > run.py
from app import create_app, db
from config import Config

app = create_app(Config)

if __name__ == '__main__':
    app.run(debug=True)
EOF

# Provide executable permissions to the script
chmod +x ../script.sh

echo "Project structure and files generated successfully."
echo "You can now activate your virtual environment and install dependencies with 'pip install -r requirements.txt'."
echo "After setting up dependencies, run the application with 'python run.py'."

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

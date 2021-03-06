from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_mail import Mail
from passkeeper.config import Config
from flask_wtf.csrf import CSRFProtect


db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()
login_manager.login_view = 'users.login'
login_manager.login_message_category = 'info'
mail = Mail()
csrf = CSRFProtect()


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    csrf.init_app(app)

    app.config["SESSION_PERMANENT"] = False
    app.config["SESSION_TYPE"] = "null"

    from passkeeper.users.routes import users
    from passkeeper.service_passwords.routes import service_passwords
    from passkeeper.main.routes import main
    from passkeeper.errors.handlers import errors
    app.register_blueprint(users)
    app.register_blueprint(service_passwords)
    app.register_blueprint(main)
    app.register_blueprint(errors)

    return app

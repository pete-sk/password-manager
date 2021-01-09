from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_mail import Mail

from app.config import Config

db = SQLAlchemy()
bcrypt = Bcrypt()
mail = Mail()

login_manager = LoginManager()
login_manager.login_view = 'account.login'
login_manager.login_message_category = 'info'


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(Config)

    app.jinja_env.trim_blocks = True
    app.jinja_env.lstrip_blocks = True

    db.init_app(app)
    bcrypt.init_app(app)
    mail.init_app(app)
    login_manager.init_app(app)

    from app.main.routes import main
    from app.errors.handlers import errors
    from app.account.routes import account
    from app.user_data.routes import user_data
    from app.blog.routes import blog
    from app.api.routes import api

    app.register_blueprint(main)
    app.register_blueprint(errors)
    app.register_blueprint(account)
    app.register_blueprint(user_data)
    app.register_blueprint(blog)
    app.register_blueprint(api)

    return app

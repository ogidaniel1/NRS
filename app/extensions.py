from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager


#database
db = SQLAlchemy()

#login and session manager
login_manager = LoginManager()
login_manager.login_view = 'users.login'
login_manager.login_message_category = 'info'

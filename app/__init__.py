from flask import Flask
from flask_cors import CORS

#local imports
from app.config import load_config
from app.extensions import db, login_manager


def create_app():
    app = Flask(__name__)
    config_class = load_config()
    app.config.from_object(config_class)

    # register/ initialize extensions
    db.init_app(app)
    CORS(app, supports_credentials=True)
    login_manager.init_app(app)

    # register routes and modules
    from app.landing import landing_bp

    routes_list = [landing_bp, ]

    for route_obj in routes_list:
        app.register_blueprint(route_obj)

    return app

from flask import Flask, redirect, url_for
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

    @app.route('/db_init', methods=['GET'])
    def db_init():
        with app.app_context():
            db.drop_all()
            db.create_all()
            return redirect(url_for('landing.home'))

    return app

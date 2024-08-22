import os
import logging

from dotenv import load_dotenv

load_dotenv()
logging.basicConfig(level = logging.INFO)


class Config:
    """Base config."""
    SECRET_KEY = os.environ.get('SECRET_KEY')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    DB_URI = ''#get_db_url()
    SQLALCHEMY_DATABASE_URI = DB_URI
    ROWS_PER_PAGE = 20
    CORS_HEADERS = 'Content-Type'


class DevConfig(Config):
    """Development config. For venv on local"""
    FLASK_ENV = "development"
    FLASK_DEBUG = True


class TestConfig(Config):
    """Testing config. for docker in local"""
    TESTING = True
    FLASK_DEBUG = True


class ProdConfig(Config):
    """Production config."""
    FLASK_ENV = "production"
    FLASK_DEBUG = False
    ROWS_PER_PAGE = 20


config_classes={"development":DevConfig, "testing": TestConfig,
                "production": ProdConfig}

def load_config():
    ENVIRONMENT = os.environ.get("ENVIRONMENT")
    env_config = config_classes[ENVIRONMENT.lower()]
    return env_config


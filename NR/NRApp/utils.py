import os
from urllib.parse import urlencode

def load_config():
    """
    Loads database configuration from environment variables.

    Raises:
        KeyError: If a required environment variable is missing.
    """

    config = {
        'host': os.environ.get('DB_HOST', 'hoghidan1.mysql.pythonanywhere-services.com'),
        'user': os.environ.get('DB_USER', 'hoghidan1'),
        'password': os.environ.get('DB_PASSWORD', 'english92'),
        'database': os.environ.get('DB_NAME', 'users'),
        'port': os.environ.get('DB_PORT', 3306)  # Default to 3306 for MySQL
    }

    # Validate required environment variables
    for key, value in config.items():
        if value is None:
            raise KeyError(f"Missing required environment variable: {key}")

    return config

def generate_db_uri():
    """
    Generates the database connection URI from environment variables.

    Returns:
        str: The constructed database connection URI.

    Raises:
        KeyError: If a required environment variable is missing.
    """

    config = load_config()
    params = urlencode({
        'charset': 'utf8'  # Optional, include charset for clarity
    })
    return f"mysql+pymysql://{config['user']}:{config['password']}@" \
           f"{config['host']}:{config['port']}/{config['database']}?{params}"


# install PyMySQL 
# #generate database connect URI
# def generate_db_uri() -> str:
#     config = load_config()['DB']
#     return f"mysql+pymysql://{config['hoghidan1']}:{config['english92']}@{config['hoghidan1.mysql.pythonanywhere-services.com']}:{config['3306']}/{config['users']}"
 

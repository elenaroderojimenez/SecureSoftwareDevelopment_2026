from flask import Flask

from .config import Config
from .database import initialise_database
from .controllers.auth_controller import register_auth_routes
from .controllers.api_controller import register_api_routes
from .controllers.file_controller import register_file_routes


def create_app():
    app = Flask(__name__, template_folder="../templates")
    app.config.from_object(Config)

    initialise_database(app.config["DATABASE"])
    register_auth_routes(app)
    register_api_routes(app)
    register_file_routes(app)

    return app

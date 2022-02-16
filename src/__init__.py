from flask import Flask, url_for
from src.routes import app
from dotenv import load_dotenv
import os
from flasgger import Swagger, swag_from
from src.config.swagger import template, swagger_config

load_dotenv()
DB_PATH = os.getenv("SQL_ALCHEMY_URI")


def create_app():
    mainapp = Flask(__name__)
    mainapp.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    mainapp.config["SQLALCHEMY_DATABASE_URI"] = "{}".format(DB_PATH)
    mainapp.config["SWAGGER"]={
        'title' : "Basic User Authentication REST API",
        'uiversion': 3
    }

    # Swagger(mainapp,config=swagger_config,template=template)

    # models
    from src.models import db, marsh

    db.app = mainapp
    db.init_app(mainapp)
    marsh.init_app(mainapp)

    mainapp.register_blueprint(app)

    return mainapp

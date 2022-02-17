from flask import Flask, url_for
from src.routes import app
from dotenv import load_dotenv
import os

load_dotenv()
DB_PATH = os.getenv("SQL_ALCHEMY_URI")


def create_app():
    mainapp = Flask(__name__)
    mainapp.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    mainapp.config["SQLALCHEMY_DATABASE_URI"] = "{}".format(DB_PATH)
    
    from src.models import db, marsh

    db.app = mainapp
    db.init_app(mainapp)
    marsh.init_app(mainapp)

    mainapp.register_blueprint(app)
    

    return mainapp

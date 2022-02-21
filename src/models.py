from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
import jwt
from time import time
import os
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.environ.get("SECRET_KEY")


db = SQLAlchemy()
marsh = Marshmallow()

"""Models"""
class User(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String, nullable=False)
    email = db.Column(db.String(60), nullable=False)
    contact_number = db.Column(db.String(12), nullable=False)
    isVerified = db.Column(db.Boolean, default=False)
    otp = db.Column(db.String, nullable=True)
    otp_released = db.Column(db.FLOAT(precision=15), nullable=True)

    def get_reset_password_token(self, expires_in=300):
        return jwt.encode(
            {"reset_password": self.id, "exp": time() + expires_in},
            "{}".format(SECRET_KEY),
            algorithm="HS256",
        )

    def verify_reset_password_token(token):
        try:
            id = jwt.decode(token, "{}".format(SECRET_KEY), algorithms=["HS256"])[
                "reset_password"
            ]
        except:
            return
        return User.query.get(id)

    def __init__(self, username, password, email, contact_number):
        self.username = username
        self.password = password
        self.email = email
        self.contact_number = contact_number


class UserSchema(marsh.Schema):
    class Meta:
        fields = ("username", "email", "contact_number", "isVerified", "otp")


class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    content = db.Column(db.String, nullable=False)

    def __init__(self, name, content):
        self.name = name
        self.content = content


class PostSchema(marsh.Schema):
    class Meta:
        fields = ("name", "content")


SingleSerializedUser = UserSchema()
MutlipleSerializedUsers = UserSchema(many=True)

SinglePosts = PostSchema()
MultiplePosts = PostSchema(many=True)

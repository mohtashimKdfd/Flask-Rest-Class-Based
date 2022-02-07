from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
import jwt
from time import time

db = SQLAlchemy()
marsh = Marshmallow()

class User(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    username = db.Column(db.String(50),nullable=False,unique=True)
    password = db.Column(db.String,nullable=False)
    email = db.Column(db.String(60),nullable=False)
    contact_number = db.Column(db.String(12),nullable=False)
    isVerified = db.Column(db.Boolean,default=False)
    otp = db.Column(db.String,nullable=True)

    def get_reset_password_token(self, expires_in=600):
        return jwt.encode(
            {'reset_password': self.id, 'exp': time() + expires_in},
            'secret', algorithm='HS256')

    def verify_reset_password_token(token):
        try:
            id = jwt.decode(token, 'secret',
                            algorithms=['HS256'])['reset_password']
        except:
            return
        return User.query.get(id)

    def __init__(self,username,password,email,contact_number):
        self.username = username
        self.password = password
        self.email = email
        self.contact_number= contact_number
        # self.isVerified = False
        # self.otp = None 
class UserSchema(marsh.Schema):
    class Meta:
        fields = ('username', 'email','contact_number', 'isVerified','otp')
    


SingleSerializedUser = UserSchema()
MutlipleSerializedUsers = UserSchema(many=True)
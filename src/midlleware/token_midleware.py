import os
import jwt
from flask import request
import jwt
import os
from dotenv import load_dotenv
from src.models import User
from functools import wraps,update_wrapper


load_dotenv()

SECRET_KEY = os.environ.get('SECRET_KEY')

def verify_token():
    def decorators(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if 'token' not in request.headers:
                return ({"Error": "A valid token is required"})
            token = request.headers['token']
            try:
                email = jwt.decode(token,'{}'.format(SECRET_KEY),algorithms='HS256')['email']
            except:
                return ({"Error": "Invalid or Expired Token"})
            targetUser = User.query.filter_by(email=email).first()
            if targetUser.isVerified == False:
                return ({"Error": "User not verified. Verify using otp"})
            return f(*args,**kwargs)
        return update_wrapper(wrapper,f)
    return decorators
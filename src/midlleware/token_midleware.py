import os
import jwt
from flask import request
import jwt
import os
from dotenv import load_dotenv
from src.models import User
from functools import wraps,update_wrapper
from src.config.error_codes import error

load_dotenv()

SECRET_KEY = os.environ.get('SECRET_KEY')

def verify_token():
    def decorators(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if 'token' not in request.headers:
                return (
                    {
                        "Status": error['401'],
                        "Error": "A valid token is required"
                }
                )
            token = request.headers['token']
            try:
                email = jwt.decode(token,'{}'.format(SECRET_KEY),algorithms='HS256')['email']
            except:
                return ({
                    "status": error['401'],
                    "Error": "Invalid or Expired Token"
                })
            targetUser = User.query.filter_by(email=email).first()
            if targetUser.isVerified == False:
                return ({
                    "status": error['401'],
                    "Error": "User not verified. Verify using otp"
                    })
            return f(*args,**kwargs)
        return update_wrapper(wrapper,f)
    return decorators
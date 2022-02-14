from flask import request
from functools import wraps
from http import HTTPStatus

def isValidRequestOtpLogin(f):
    @wraps(f)
    def validate(*args, **kwargs):
        if "email" not in request.json:
            return {"msg": "Email not found"}, 400
        if "otp" not in request.json:
            return {"msg": "Otp not found"}, 400
        return f(*args, **kwargs)
    return validate
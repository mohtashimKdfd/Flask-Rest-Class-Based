from flask import request
from functools import wraps
from http import HTTPStatus

def isValidRequestLogin(f):
    @wraps(f)
    def validate(*args, **kwargs):
        # if "username" not in request.json:
        #     return {"msg": "Username not found"}, HTTPStatus.BAD_REQUEST
        if "email" not in request.json:
            return {"msg": "Email not found"}, HTTPStatus.BAD_REQUEST
        if "password" not in request.json:
            return {"msg": "Password not found"}, HTTPStatus.BAD_REQUEST
        return f(*args, **kwargs)
    return validate
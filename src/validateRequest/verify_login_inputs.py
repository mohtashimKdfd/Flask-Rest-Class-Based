from flask import request
from functools import wraps
from http import HTTPStatus
from loguru import logger
def isValidRequestLogin(f):
    @wraps(f)
    def validate(*args, **kwargs):
        # if "username" not in request.json:
        #     return {"msg": "Username not found"}, 400
        if "email" not in request.json:
            logger.info("{} {}".format(request,request.method))
            logger.warning("Request must have email")
            return {
                "Error": "400 Bad Request",
                "Description": "Email not found"
            }, 400
        if "password" not in request.json:
            logger.info("{} {}".format(request,request.method))
            logger.warning("Request must have password")
            return {
                "Error": "400 Bad Request",
                "Description": "Password not found"
            }, 400
        return f(*args, **kwargs)
    return validate
from flask import request
from functools import wraps
from http import HTTPStatus
from loguru import logger
from src.config.error_codes import error
def isValidRequestSignup(f):
    @wraps(f)
    def validate(*args, **kwargs):
        if "username" not in request.json:
            logger.info("{} {}".format(request,request.method))
            logger.warning("Request must have username")
            return {
                "Error": error["400"],
                "Description": "Username not found"
            }, 400
        if "password" not in request.json:
            logger.info("{} {}".format(request,request.method))
            logger.warning("Request must have password")
            return {
                "Error": error["400"],
                "Description": "Password not found"
            }, 400
        if "email" not in request.json:
            logger.info("{} {}".format(request,request.method))
            logger.warning("Request must have email")
            return {
                "Error": error["400"],
                "Description": "Email not found"
            }, 400
        return f(*args, **kwargs)
    return validate
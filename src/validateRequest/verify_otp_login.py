from flask import request
from functools import wraps
from http import HTTPStatus
from loguru import logger
from src.config.error_codes import error

def isValidRequestOtpLogin(f):
    @wraps(f)
    def validate(*args, **kwargs):
        if "email" not in request.json:
            logger.info("{} {}".format(request,request.method))
            logger.warning("Request must have email")
            return {
                "Error": error["400"],
                "Description": "Email not found"
            }, 400
        if "otp" not in request.json:
            logger.info("{} {}".format(request,request.method))
            logger.warning("Request must have otp")
            return {
                "Error": error["400"],
                "Description": "Otp not found"
            }, 400
        return f(*args, **kwargs)
    return validate
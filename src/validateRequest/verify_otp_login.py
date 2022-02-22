from flask import request
from functools import wraps
from http import HTTPStatus
from loguru import logger
def isValidRequestOtpLogin(f):
    @wraps(f)
    def validate(*args, **kwargs):
        if "email" not in request.json:
            logger.info("{} {}".format(request,request.method))
            logger.warning("Request must have email")
            return {
                "Error": "400 Bad Request",
                "Description": "Email not found"
            }, 400
        if "otp" not in request.json:
            logger.info("{} {}".format(request,request.method))
            logger.warning("Request must have otp")
            return {
                "Error": "400 Bad Request",
                "Description": "Otp not found"
            }, 400
        return f(*args, **kwargs)
    return validate
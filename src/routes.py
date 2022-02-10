from time import time
from flask import Blueprint, request, render_template, url_for, make_response
from werkzeug.security import generate_password_hash, check_password_hash
# from flask_restful import Api, Resource
from flask_restx import Api, Resource
from src.models import db, User, SingleSerializedUser, Posts, SinglePosts, MultiplePosts
from src.services.mailers import SendMail, send_password_reset_email, SendResetMail
from src.services.textmsg import SendOtp
import random
import jwt
import os
from dotenv import load_dotenv

# for http status codes
from http import HTTPStatus

load_dotenv()

SECRET_KEY = os.environ.get("SECRET_KEY")

# email validation
from src.checks.valid_email import verify_email

# otp validation
from src.checks.valid_otp import verify_otp

# password validation
from src.checks.valid_password import verify_password

# token validation
from src.midlleware.token_midleware import verify_token

# for logging and
from loguru import logger

app = Blueprint("app", __name__) 
api = Api(app)


@api.route('/')
class Home(Resource):
    def get(self):
        return {"msg": "Hello, world!"}

@api.route('/signup')
class Signup(Resource):
    def post(self):
        logger.debug('Signup : {}'.format(request.method),request)
        if "username" not in request.json:
            return {"msg": "Username not found"}, HTTPStatus.BAD_REQUEST
        if "password" not in request.json:
            return {"msg": "Password not found"}, HTTPStatus.BAD_REQUEST
        if "email" not in request.json:
            return {"msg": "Email not found"}, HTTPStatus.BAD_REQUEST

        username = request.json["username"]
        password = request.json["password"]
        if verify_password(password) == False:
            return {
                "Password Verification failed": "Password should be 6-18 characters long and should contain atleast one upper case character, one lower case character and one special character(!,@,#,&) and should not contain empty spaces"
            }, HTTPStatus.FORBIDDEN

        hashed_password = generate_password_hash(password)
        email = request.json["email"]
        if verify_email(email) == False:
            return (
                ({"Email Error": "Invalid email address"}),
                HTTPStatus.FORBIDDEN,
            )

        contact_number = request.json["contact_number"]
        if User.query.filter_by(username=username).count():
            return (
                ({"Username error": "username already registered"}),
                HTTPStatus.CONFLICT,
            )
        else:
            newUser = User(
                username=username,
                password=hashed_password,
                email=email,
                contact_number=contact_number,
            )
            try:
                SendMail(email, "Your account has been created"), HTTPStatus.CREATED
                db.session.add(newUser)
                db.session.commit()

                return SingleSerializedUser.jsonify(newUser)
            except Exception as e:
                print(e)
                return (
                    ({"msg": "Unable to create User"}),
                    HTTPStatus.NOT_ACCEPTABLE,
                )

    def get(self):
        logger.debug('Signup : {}'.format(request.method),request)
        return ({"msg": "Method not allowed"}), HTTPStatus.METHOD_NOT_ALLOWED

@api.route('/login')
class Login(Resource):
    def post(self):
        logger.debug('Login : {}'.format(request.method),request)
        if "email" not in request.json:
            return {"Email error": "Email not found"}, HTTPStatus.BAD_REQUEST
        if "password" not in request.json:
            return {"Password error": "Password not found"}, HTTPStatus.BAD_REQUEST

        email = request.json["email"]
        password = request.json["password"]

        if verify_password(password) == False:
            return {
                "Password Verification failed": "Password should be 6-18 characters long and should contain atleast one upper case character, one lower case character and one special character(!,@,#,&) and should not contain empty spaces"
            }, HTTPStatus.FORBIDDEN

        if User.query.filter_by(email=email).count():
            targetUser = User.query.filter_by(email=email).first()
            if check_password_hash(targetUser.password, password) == True:
                if targetUser.isVerified == False:
                    one_time_password = random.randint(1000, 9999)
                    targetUser.otp = one_time_password
                    targetUser.otp_released = time()
                    db.session.commit()
                    SendOtp(one_time_password, targetUser.contact_number)
                    SendMail(
                        targetUser.email,
                        "Your One time password is {}".format(one_time_password),
                    )

                    login_token = jwt.encode(
                        {"email": targetUser.email, "exp": time() + 300},
                        "{}".format(SECRET_KEY, algorithms="HS256"),
                    )

                    return (
                        (
                            {
                                "Otp message": "Otp sent successfully on your registered mobile number and email and is valid for 5 minutes .Please provide the same.",
                                "token": login_token,
                            }
                        ),
                        HTTPStatus.OK,
                    )

                else:
                    return ({"msg": "User Logged in"}), HTTPStatus.ACCEPTED
            else:
                return ({"msg": "Wrong Password"}), HTTPStatus.UNAUTHORIZED
        else:
            return ({"msg": "User not registered"}), HTTPStatus.NOT_FOUND

    def get(self):
        logger.debug('Login : {}'.format(request.method),request)
        return ({"msg": "Method not allowed"}), HTTPStatus.METHOD_NOT_ALLOWED

@api.route('/OtpLogin')
class LoginWithOtp(Resource):
    def post(self):
        logger.debug('LoginWithOtp : {}'.format(request.method),request)
        if "otp" not in request.json:
            return ({"msg": "Otp not provided"}), HTTPStatus.BAD_REQUEST
        if "email" not in request.json:
            return {"msg": "Email not found"}, HTTPStatus.BAD_REQUEST
        email = request.json["email"]
        otp_provided = request.json["otp"]
        if User.query.filter_by(email=email).count():
            targetUser = User.query.filter_by(email=email).first()
            if verify_otp(targetUser, otp_provided) == True:
                targetUser.isVerified = True
                targetUser.otp_released = None
                db.session.commit()
                return (
                    ({"msg": "OTP verified successfully || User logged in"}),
                    HTTPStatus.ACCEPTED,
                )
            else:
                return (
                    ({"msg": "Invalid otp provided or Otp Expired"}),
                    HTTPStatus.GONE,
                )
        else:
            return ({"msg": "User not found"}), HTTPStatus.NOT_FOUND

    def get(self):
        logger.debug('LoginWithOtp : {}'.format(request.method),request)
        return ({"msg": "Method not allowed"}), HTTPStatus.METHOD_NOT_ALLOWED

@api.route('/change_status')
class ChangeVerifiedStatus(Resource):
    def post(self):
        logger.debug('ChangeVerifiedStatus : {}'.format(request.method),request)
        if "email" not in request.json:
            return {"msg": "Email not found"}
        email = request.json["email"]
        targetUser = User.query.filter_by(email=email).first()
        targetUser.isVerified = False
        db.session.commit()

        return ({"msg": "status changed to False"}), HTTPStatus.OK
    def get(self):
        logger.debug('ChangeVerifiedStatus : {}'.format(request.method),request)
        return ({"msg": "Method not allowed"}), HTTPStatus.METHOD_NOT_ALLOWED

@api.route('/OtpLogin')

class ResetPasswordRequest(Resource):
    def post(self):
        logger.debug('ResetPasswordRequest : {}'.format(request.method),request)
        if "email" not in request.json:
            return {"msg": "Email not found"}, HTTPStatus.BAD_REQUEST
        email = request.json["email"]
        user = User.query.filter_by(email=email).first()
        if user:
            send_password_reset_email(user)
            return ({"msg": "A link to reset password has been sent to your registered email id and is valid for 5 minutes only "}), HTTPStatus.ACCEPTED
        else:
            return ({"msg": "User not found"}), HTTPStatus.UNAUTHORIZED
    def get(self):
        logger.debug('ResetPasswordRequest : {}'.format(request.method),request)
        return ({"msg": "Method not allowed"}), HTTPStatus.METHOD_NOT_ALLOWED

@api.route('/reset_password/<token>')
class ResetPassword(Resource):
    def post(self, token):
        logger.debug('ResetPassword : {}'.format(request.method),request)
        user = User.verify_reset_password_token(token)
        if not user:
            return ({"msg": "No user found"}), HTTPStatus.UNAUTHORIZED

        password = request.form["password"]
        if verify_password(password) == False:
            return ({"Password Verification failed": "Password should be 6-18 characters long and should contain atleast one upper case character, one lower case character and one special character(!,@,#,&) and should not contain empty spaces"})
        user.password = generate_password_hash(password)
        db.session.commit()
        return ({"msg": "Password Changed"}), HTTPStatus.ACCEPTED

    def get(self, token):
        logger.debug('ResetPassword : {}'.format(request.method),request)
        user = User.verify_reset_password_token(token)
        if not user:
            return ({"error" : "Token expired or invalid user"}) , HTTPStatus.UNAUTHORIZED
        return make_response(render_template("reset.html"))

@api.route('/posts')
class PostRoutes(Resource):
    decorators = [verify_token]

    def get(self, *args, **kwargs):
        logger.debug('PostRoutes : {}'.format(request.method),request)

        all_posts = Posts.query.all()
        return MultiplePosts.jsonify(all_posts)

    def post(self):
        logger.debug('PostRoutes : {}'.format(request.method),request)

        name = request.json["name"]
        content = request.json["content"]

        newPost = Posts(name=name, content=content)
        db.session.add(newPost)
        db.session.commit()

        return (SinglePosts.jsonify(newPost))

# ALl routes

# api.add_resource(Home, "/")
# api.add_resource(Signup, "/signup")
# api.add_resource(Login, "/login")
# api.add_resource(LoginWithOtp, "/OtpLogin")
# api.add_resource(ChangeVerifiedStatus, "/change_status")
# api.add_resource(ResetPasswordRequest, "/reset_password_request")
# api.add_resource(ResetPassword, "/reset_password/<token>")
# api.add_resource(PostRoutes, "/posts")

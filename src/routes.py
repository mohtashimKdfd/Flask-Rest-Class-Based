from time import time
from flask import Blueprint, request, render_template, url_for, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from flask_restx import Api, Resource
from src.models import db, User, SingleSerializedUser, Posts, SinglePosts, MultiplePosts
from src.services.mailers import SendMail, send_password_reset_email, SendResetMail
from src.services.textmsg import SendOtp
import random
import jwt
import os
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.environ.get("SECRET_KEY")

# email validation
from src.checks.valid_email import verify_email

# otp validation
from src.checks.valid_otp import verify_otp

# password validation
from src.checks.valid_password import verify_password

#Validate Username
from src.checks.valid_credentials import isUniqueUser, isRegisteredUser

# token validation
from src.midlleware.token_midleware import verify_token
from src.midlleware.auth import authorize

# for logging and
from loguru import logger

#for validating requests
from src.validateRequest.verify_signup_inputs import isValidRequestSignup
from src.validateRequest.verify_login_inputs import isValidRequestLogin
from src.validateRequest.verify_otp_login import isValidRequestOtpLogin

#for parsing requests
from src.parsers.all_parsers import signup_parser, login_parser, otp_parser


app = Blueprint("app", __name__) 
api = Api(app)


@api.route('/')
class Home(Resource):
    def get(self):
        return {"msg": "Hello, world!"}

@api.route('/signup')
class Signup(Resource):
    """ Used signup parser(reqparse) that allows us to access 
        user inputs from requests
        Used a decorator(isValidRequestSignup) that handles throwing
        error and gives formated response to insufficient user inputs 
    """
    @api.expect(signup_parser)
    @isValidRequestSignup
    def post(self):
        args = signup_parser.parse_args()

        logger.debug('Signup : {}'.format(request.method),request)

        username = args['username']
        password = args['password']
        if verify_password(password) == False:
            return {
                "Password Verification failed": "Password should be 6-18 characters long and should contain atleast one upper case character, one lower case character and one special character(!,@,#,&) and should not contain empty spaces"
            }, 403

        hashed_password = generate_password_hash(password)
        email = args['email']
        if verify_email(email) == False:
            return (
                ({"Email Error": "Invalid email address"}),
                403,
            )
        contact_number = args['contact_number']
        if isUniqueUser(username,email)==False: return ({"Error":"A user with the same username and email already exists"})

        
        newUser = User(
            username=username,
            password=hashed_password,
            email=email,
            contact_number=contact_number,
        )
        try:
            SendMail(email, "Your account has been created"), 201
            db.session.add(newUser)
            db.session.commit()

            return SingleSerializedUser.jsonify(newUser)
        except Exception as e:
            print(e)
            return (
                ({"msg": "Unable to create User"}),
                406,
            )

    def get(self):
        logger.debug('Signup : {}'.format(request.method),request)
        return ({"msg": "Method not allowed"}), 405

@api.route('/login')
class Login(Resource):
    """ Used login parser(reqparse) that allows us to access 
        user inputs from requests
        Used a decorator(isValidRequestLogin) that handles throwing
        error and gives formated response to insufficient user inputs 
    """
    @api.expect(login_parser)
    @isValidRequestLogin
    def post(self):
        logger.debug('Login : {}'.format(request.method),request)
        args = login_parser.parse_args()

        email = args['email']
        password = args['password']

        if verify_password(password) == False:
            return {
                "Password Verification failed": "Password should be 6-18 characters long and should contain atleast one upper case character, one lower case character and one special character(!,@,#,&) and should not contain empty spaces"
            }, 403

        if isRegisteredUser(email)==False:
            return ({"Error": "Invalid email address"})

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
                return (
                    (
                        {
                            "Otp message": "Otp sent successfully on your registered mobile number and email and is valid for 5 minutes .Please provide the same."
                        }
                    ),
                    200,
                )

            else:
                login_token = jwt.encode(
                    {"email": targetUser.email, "exp": time() + 300},
                    "{}".format(SECRET_KEY, algorithms="HS256"),
                )
                return (
                    { 
                        "msg":"User Logged in",
                        "token": login_token
                    }
                ),200
        else:
            return ({"msg": "Wrong Password"}), 401

    def get(self):
        logger.debug('Login : {}'.format(request.method),request)
        return ({"msg": "Method not allowed"}), 405

@api.route('/OtpLogin')
class LoginWithOtp(Resource):
    """ Used loginOtp parser(reqparse) that allows us to access 
        user inputs from requests
        Used a decorator(isValidRequestOtpLogin) that handles throwing
        error and gives formated response to insufficient user inputs 
    """
    @api.expect(otp_parser)
    @isValidRequestOtpLogin
    def post(self):
        logger.debug('LoginWithOtp : {}'.format(request.method),request)
        
        args = otp_parser.parse_args()
        email = args["email"]
        otp_provided = args["otp"]
        if User.query.filter_by(email=email).count():
            targetUser = User.query.filter_by(email=email).first()
            if verify_otp(targetUser, otp_provided) == True:
                targetUser.isVerified = True
                targetUser.otp_released = None
                db.session.commit()
                login_token = jwt.encode(
                    {"email": targetUser.email, "exp": time() + 300},
                    "{}".format(SECRET_KEY, algorithms="HS256"),
                )
                return (
                    { 
                        "msg":"User Logged in",
                        "token": login_token
                    }
                ),200
            else:
                return (
                    ({"msg": "Invalid otp provided or Otp Expired"}),
                    410,
                )
        else:
            return ({"msg": "User not found"}), 404

    def get(self):
        logger.debug('LoginWithOtp : {}'.format(request.method),request)
        return ({"msg": "Method not allowed"}), 405

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

        return ({"msg": "status changed to False"}), 200
    def get(self):
        logger.debug('ChangeVerifiedStatus : {}'.format(request.method),request)
        return ({"msg": "Method not allowed"}), 405

@api.route('/OtpLogin')

class ResetPasswordRequest(Resource):
    def post(self):
        logger.debug('ResetPasswordRequest : {}'.format(request.method),request)
        if "email" not in request.json:
            return {"msg": "Email not found"}, 400
        email = request.json["email"]
        user = User.query.filter_by(email=email).first()
        if user:
            send_password_reset_email(user)
            return ({"msg": "A link to reset password has been sent to your registered email id and is valid for 5 minutes only "}), 202
        else:
            return ({"msg": "User not found"}), 401
    def get(self):
        logger.debug('ResetPasswordRequest : {}'.format(request.method),request)
        return ({"msg": "Method not allowed"}), 405

@api.route('/reset_password/<token>')
class ResetPassword(Resource):
    def post(self, token):
        logger.debug('ResetPassword : {}'.format(request.method),request)
        user = User.verify_reset_password_token(token)
        if not user:
            return ({"msg": "No user found"}), 401

        password = request.form["password"]
        if verify_password(password) == False:
            return ({"Password Verification failed": "Password should be 6-18 characters long and should contain atleast one upper case character, one lower case character and one special character(!,@,#,&) and should not contain empty spaces"})
        user.password = generate_password_hash(password)
        db.session.commit()
        return ({"msg": "Password Changed"}), 202

    def get(self, token):
        logger.debug('ResetPassword : {}'.format(request.method),request)
        user = User.verify_reset_password_token(token)
        if not user:
            return ({"error" : "Token expired or invalid user"}) , 401
        return make_response(render_template("reset.html"))

@api.route('/posts')
class PostRoutes(Resource):
    @verify_token
    @authorize(roles=("admin",'normal'))
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



from time import time
from flask import Blueprint, request, jsonify, render_template, url_for, make_response
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

#for swagger
from flasgger import Swagger, swag_from
from src.config.swagger import template, swagger_config

#for pagination
from src.pagination_folder.paginater import generate_data

app = Blueprint("app", __name__) 
api = Api(app)



@api.route('/home')
class Home(Resource):
    @swag_from('docs/home/main.yml')
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
                "Error" :"403",
                "Description":"Password Verification failed",
                "Meta Data": "Password should be 6-18 characters long and should contain atleast one upper case character, one lower case character and one special character(!,@,#,&) and should not contain empty spaces"
            }, 403

        hashed_password = generate_password_hash(password)
        email = args['email']
        if verify_email(email) == False:
            return (
                ({
                    "Error":"403",
                    "Description":"Email Error",
                    "Meta Data": "Invalid email address"
                }),403,
            )
        contact_number = args['contact_number']
        if isUniqueUser(username,email)==False: return ({"Error":"403","Error":"A user with the same username and email already exists"}),403

        
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
                ({  "Error":"406",
                    "msg": "Unable to create User"}),
                406,
            )

    def get(self):
        logger.debug('Signup : {}'.format(request.method),request)
        return ({"Error":"405","msg": "Method not allowed"}), 405

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
                "Error" :"403",
                "Description":"Password Verification failed",
                "Meta Data": "Password should be 6-18 characters long and should contain atleast one upper case character, one lower case character and one special character(!,@,#,&) and should not contain empty spaces"
            }, 403

        if isRegisteredUser(email)==False:
            return ({
                "Error":"400",
                "Description":"Invalid email address",
                "Meta Data": "No user registered with this email address"}) ,400

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
                            "Status":"200",
                            "Description": "Otp sent successfully",
                            "Meta Data": "Otp sent successfully on your registered mobile number and email and is valid for 5 minutes .Please provide the same."
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
                        "Status":"200",
                        "Description":"User Logged in",
                        "token": login_token,
                        "Meta Data": "Please use the above token to access your account"
                    }
                ),200
        else:
            return ({
                "Error":"401","Description": "Wrong Password"}), 401

    def get(self):
        logger.debug('Login : {}'.format(request.method),request)
        return ({
            "Error": "405",
            "msg": "Method not allowed"}), 405

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
                        "Status":"200",
                        "Description":"User Logged in",
                        "token": login_token
                    }
                ),200
            else:
                return (
                    ({  "Error":"410",
                        "Description": "Invalid otp provided or Otp Expired"}),
                    410,
                )
        else:
            return ({"Error":"404","Description": "User not found"}), 404

    def get(self):
        logger.debug('LoginWithOtp : {}'.format(request.method),request)
        return ({"Error":"405","msg": "Method not allowed"}), 405

@api.route('/change_status')
class ChangeVerifiedStatus(Resource):
    def post(self):
        logger.debug('ChangeVerifiedStatus : {}'.format(request.method),request)
        if "email" not in request.json:
            return {"Error":"400","Description": "Email not found"}, 400
        email = request.json["email"]
        targetUser = User.query.filter_by(email=email).first()
        targetUser.isVerified = False
        db.session.commit()

        return ({"Status":"200","Description": "status changed to False"}), 200
    def get(self):
        logger.debug('ChangeVerifiedStatus : {}'.format(request.method),request)
        return ({"Erro":"405","Description": "Method not allowed"}), 405

@api.route('/OtpLogin')

class ResetPasswordRequest(Resource):
    def post(self):
        logger.debug('ResetPasswordRequest : {}'.format(request.method),request)
        if "email" not in request.json:
            return {"Error":"400","Description": "Email not found"}, 400
        email = request.json["email"]
        user = User.query.filter_by(email=email).first()
        if user:
            send_password_reset_email(user)
            return ({"Status":"200","msg": "A link to reset password has been sent to your registered email id and is valid for 5 minutes only "}), 202
        else:
            return ({"Error":"401","Description": "User not found"}), 401
    def get(self):
        logger.debug('ResetPasswordRequest : {}'.format(request.method),request)
        return ({"Error":"405","Description": "Method not allowed"}), 405

@api.route('/reset_password/<token>')
class ResetPassword(Resource):
    def post(self, token):
        logger.debug('ResetPassword : {}'.format(request.method),request)
        user = User.verify_reset_password_token(token)
        if not user:
            return ({"Error":"401","Description": "No user found"}), 401

        password = request.form["password"]
        if verify_password(password) == False:
            return {
                "Error" :"403",
                "Description":"Password Verification failed",
                "Meta Data": "Password should be 6-18 characters long and should contain atleast one upper case character, one lower case character and one special character(!,@,#,&) and should not contain empty spaces"
            }, 403
        user.password = generate_password_hash(password)
        db.session.commit()
        return ({"Status":"202","Description": "Password Changed"}), 202

    def get(self, token):
        logger.debug('ResetPassword : {}'.format(request.method),request)
        user = User.verify_reset_password_token(token)
        if not user:
            return ({"error":"401","Description": "Token expired or invalid user"}) , 401
        return make_response(render_template("reset.html"))

@api.route('/posts')
class PostRoutes(Resource):
    """
        Verify token makes sure a valid jwt token is provided in the header of request
        authorize decorator defines roles based access control
    """
    # @verify_token
    @authorize(roles=('admin','normal'))
    # @swag_from('docs/posts/get.yaml')
    def get(self, *args, **kwargs):
        logger.debug('PostRoutes : {}'.format(request.method),request)
        
        '''
            Pagination
            Page represents currpage
            Per_page shows the number of posts to show in current page
        '''
        

        meta_data=[]
        

        return (generate_data())
    
    # @swag_from('docs/posts/post.yaml')
    def post(self):
        logger.debug('PostRoutes : {}'.format(request.method),request)

        name = request.json["name"]
        content = request.json["content"]

        newPost = Posts(name=name, content=content)
        db.session.add(newPost)
        db.session.commit()

        return (SinglePosts.jsonify(newPost))
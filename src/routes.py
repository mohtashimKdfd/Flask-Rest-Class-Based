from time import time
from flask import Blueprint, request, jsonify, render_template, url_for, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from flask_restx import Api, Resource, Namespace
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
import loguru

#for validating requests
from src.validateRequest.verify_signup_inputs import isValidRequestSignup
from src.validateRequest.verify_login_inputs import isValidRequestLogin
from src.validateRequest.verify_otp_login import isValidRequestOtpLogin

#for parsing requests
from src.parsers.all_parsers import signup_parser, login_parser, otp_parser

#handling errors
from src.config.error_codes import error



#for pagination
from src.pagination_folder.paginater import generate_data

#Logging

loguru.logger.add(
    "loguru.log",
    level="INFO",
    format="{time} {level} {message}",
    retention='1 minute',
)
loguru.logger.info('Loguru is up and running')

@loguru.logger.catch()
def log_exception():
    try:
        print(2+20)
    except Exception as e:  
        raise Exception(e)
log_exception()

app = Blueprint("app", __name__) 
api = Api(app)


authorizations = {
    'api_key' : {
        'type' : 'apiKey',
        'in' : 'header',
        'name' : 'token'
    }
}


homespace = Namespace('Home Page',description="Introductory")
user_signup = Namespace('New User Signup',description="This is for registering new users into db")
user_login = Namespace('User Login',description="This is for existing users to login")
postspace = Namespace('Post Space',description="Fetch posts from database", authorizations=authorizations,security='api_key')

reset_password = Namespace('Reset Password',description="This is for resetting password")


api.add_namespace(homespace,path='/')
api.add_namespace(user_signup,path='/')
api.add_namespace(user_login,path="/")
api.add_namespace(postspace,path="/")
api.add_namespace(reset_password,path='/')




@homespace.route('/home')
class Home(Resource):
    @loguru.logger.catch()
    def get(self):
        try:
            return {'msg': "Hello, world!"}
        except Exception as e:
            raise Exception(e)

@user_signup.route('/signup')
class Signup(Resource):
    
    """ Used signup parser(reqparse) that allows us to access 
        user inputs from requests
        Used a decorator(isValidRequestSignup) that handles throwing
        error and gives formated response to insufficient user inputs 
    """
    @api.expect(signup_parser)
    @isValidRequestSignup
    @loguru.logger.catch() #for logging

    

    def post(self):

        '''
            The method is for the post request for new users to signup
            It takes email, password, contact_number and username and validates the inputs and adds the new user into the database
            The OTP is valid for 5 minutes and is sent to contact number of user registered and email 
        '''

        try:
            args = signup_parser.parse_args()

            logger.debug('Signup : {}'.format(request.method),request)

            username = args['username']
            password = args['password']
            if verify_password(password) == False:
                return {
                    "Error" : error['403'],
                    "Description":"Password Verification failed",
                    "Meta Data": "Password should be 6-18 characters long and should contain atleast one upper case character, one lower case character and one special character(!,@,#,&) and should not contain empty spaces"
                }, 403

            hashed_password = generate_password_hash(password)
            email = args['email']
            if verify_email(email) == False:
                return (
                    ({
                        "Error": error['403'],
                        "Description":"Email Error",
                        "Meta Data": "Invalid email address"
                    }),403,
                )
            contact_number = args['contact_number']
            if isUniqueUser(username,email)==False: return ({"Error":error['403'],"Error":"A user with the same username and email already exists"}),403

            
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

                return SingleSerializedUser.jsonify(newUser) , 201
            except Exception as e:
                print(e)
                return (
                    ({  "Error":error["406"],
                        "msg": "Unable to create User"}),
                    406,
                )
        except Exception as e:
            raise Exception(e)

    @loguru.logger.catch() #for logging
    def get(self):

        '''
            Currently this method is not allowed in development phase
        '''

        try:
            logger.debug('Signup : {}'.format(request.method),request)
            return ({"Error":error["405"],"msg": "Method not allowed"}), 405
        except Exception as e:
            raise Exception(e)

@user_login.route('/login')
class Login(Resource):
    """ Used login parser(reqparse) that allows us to access 
        user inputs from requests
        Used a decorator(isValidRequestLogin) that handles throwing
        error and gives formated response to insufficient user inputs 
    """
    @api.expect(login_parser)
    @isValidRequestLogin
    @loguru.logger.catch() #for logging
    def post(self):

        '''
            The method is for the post request for users to login
            It takes email and password and validates and then generates a 4 digit random otp_parser
            The OTP is valid for 5 minutes and is sent to contact number of user registered and email 
        '''

        try:
            logger.debug('Login : {}'.format(request.method),request)
            args = login_parser.parse_args()

            email = args['email']
            password = args['password']

            if verify_password(password) == False:
                return {
                    "Error" :error["403"],
                    "Description":"Password Verification failed",
                    "Meta Data": "Password should be 6-18 characters long and should contain atleast one upper case character, one lower case character and one special character(!,@,#,&) and should not contain empty spaces"
                }, 403

            if isRegisteredUser(email)==False:
                return ({
                    "Error":error["400"],
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
                                "Status":error["200"],
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
                            "Status":error["200"],
                            "Description":"User Logged in",
                            "token": login_token,
                            "Meta Data": "Please use the above token to access your account"
                        }
                    ),200
            else:
                return ({
                    "Error":error["401"],"Description": "Wrong Password"}), 401
        except Exception as e:
            raise Exception(e)

    @loguru.logger.catch() #for logging
    def get(self):
        '''
            Currently this method is not allowed in development phase
        '''
        try:
            logger.debug('Login : {}'.format(request.method),request)
            return ({
                "Error": error['405'],
                "msg": "Method not allowed"}), 405
        except Exception as e:
            Exception(e)

@user_login.route('/OtpLogin')
class LoginWithOtp(Resource):
    """ Used loginOtp parser(reqparse) that allows us to access 
        user inputs from requests
        Used a decorator(isValidRequestOtpLogin) that handles throwing
        error and gives formated response to insufficient user inputs 
    """
    @api.expect(otp_parser)
    @isValidRequestOtpLogin
    @loguru.logger.catch() #for logging
    def post(self):
        '''
            The method is for the post request for users to login with otp
            It takes email and otp and validates and then generates a 4 digit random otp_parser
            Once the otp is verified it changes the logged in status of user in db
        '''
        try:
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
                            "Status":error['200'],
                            "Description":"User Logged in",
                            "token": login_token
                        }
                    ),200
                else:
                    return (
                        ({  "Error":error['410'],
                            "Description": "Invalid otp provided or Otp Expired"}),
                        410,
                    )
            else:
                return ({"Error":error['404'],"Description": "User not found"}), 404
        except Exception as e:
            raise Exception(e)

    @loguru.logger.catch() #for logging
    def get(self):
        '''
            Currently this method is not allowed in development phase
        '''
        try:
            logger.debug('LoginWithOtp : {}'.format(request.method),request)
            return ({"Error":error['405'],"msg": "Method not allowed"}), 405
        except Exception as e:
            raise Exception(e)

@user_login.route('/change_status')
class ChangeVerifiedStatus(Resource):
    @loguru.logger.catch() #for logging
    def post(self):
        '''
            This route is used to change the status of a user to unverified in db.
        '''
        try:
            logger.debug('ChangeVerifiedStatus : {}'.format(request.method),request)
            if "email" not in request.json:
                return {"Error":error['400'],"Description": "Email not found"}, 400
            email = request.json["email"]
            targetUser = User.query.filter_by(email=email).first()
            targetUser.isVerified = False
            db.session.commit()

            return ({"Status":error['200'],"Description": "status changed to False"}), 200
        except Exception as e:
            raise Exception(e)
    
    @loguru.logger.catch() #for logging
    def get(self):
        '''
            Currently this method is not allowed in development phase
        '''
        try:
            logger.debug('ChangeVerifiedStatus : {}'.format(request.method),request)
            return ({"Erro":error['405'],"Description": "Method not allowed"}), 405
        except Exception as e:
            raise Exception(e)

@reset_password.route('/reset_password_request')

class ResetPasswordRequest(Resource):
    @loguru.logger.catch() #for logging
    def post(self):
        '''
            This method is used to send a reset password request to the server
        '''
        try:
            logger.debug('ResetPasswordRequest : {}'.format(request.method),request)
            if "email" not in request.json:
                return {"Error":error['400'],"Description": "Email not found"}, 400
            email = request.json["email"]
            user = User.query.filter_by(email=email).first()
            if user:
                send_password_reset_email(user)
                return ({"Status":error['200'],"msg": "A link to reset password has been sent to your registered email id and is valid for 5 minutes only "}), 202
            else:
                return ({"Error":error['401'],"Description": "User not found"}), 401
        except Exception as e:
            raise Exception(e)

    @loguru.logger.catch() #for logging
    def get(self):
        '''
            Currently this method is not allowed in development phase
        '''
        try:
            logger.debug('ResetPasswordRequest : {}'.format(request.method),request)
            return ({"Error":error['405'],"Description": "Method not allowed"}), 405
        except Exception as e:
            raise Exception(e)

@reset_password.route('/reset_password/<token>')
class ResetPassword(Resource):
    @loguru.logger.catch() #for logging
    def post(self, token):
        '''
            This method comes along with a token that validates the request and user
        '''
        try:
            logger.debug('ResetPassword : {}'.format(request.method),request)
            user = User.verify_reset_password_token(token)
            if not user:
                return ({"Error":error['401'],"Description": "No user found"}), 401

            password = request.form["password"]
            if verify_password(password) == False:
                return {
                    "Error" :error['4053'],
                    "Description":"Password Verification failed",
                    "Meta Data": "Password should be 6-18 characters long and should contain atleast one upper case character, one lower case character and one special character(!,@,#,&) and should not contain empty spaces"
                }, 403
            user.password = generate_password_hash(password)
            db.session.commit()
            return ({"Status":error['202'],"Description": "Password Changed"}), 202
        except Exception as e:
            raise Exception(e)

    @loguru.logger.catch() #for logging
    def get(self, token):
        '''
            Currently this method is used to render the sendgrid template 
        '''
        try:
            logger.debug('ResetPassword : {}'.format(request.method),request)
            user = User.verify_reset_password_token(token)
            if not user:
                return ({"error":"401","Description": "Token expired or invalid user"}) , 401
            return make_response(render_template("reset.html"))
        except Exception as e:
            raise Exception(e)

@postspace.route('/posts/<int:page>')
# @postspace.doc(security="api_key")
class PostRoutes(Resource):
    """
        Verify token makes sure a valid jwt token is provided in the header of request
        authorize decorator defines roles based access control
    """
    @verify_token()
    @authorize(roles=('admin','normal'))
    @loguru.logger.catch() #for logging
    def get(self,page,*args,**kwargs):
        '''
            This method is used to fetch data from database
        '''

        
        try:
            logger.debug('PostRoutes : {}'.format(request.method),request)
            
            '''
                Pagination
                Page represents currpage
                Per_page shows the number of posts to show in current page
            '''            
            return (generate_data(page))
            # return MultiplePosts.jsonify(Posts.query.all())
        except Exception as e:
            raise Exception(e)


    @loguru.logger.catch() #for logging
    def post(self,page):
        '''
            Currently this method is not allowed in development phase
        '''
        try:
            logger.debug('LoginWithOtp : {}'.format(request.method),request)
            return ({"Error":error['405'],"msg": "Method not allowed"}), 405
        except Exception as e:
            raise Exception(e)

@postspace.route('/newPost')
class NewPost(Resource):
    @loguru.logger.catch() #for logging
    def get(self):
        '''
            Currently this method is not allowed in development phase
        '''
        try:
            logger.debug('LoginWithOtp : {}'.format(request.method),request)
            return ({"Error":error['405'],"msg": "Method not allowed"}), 405
        except Exception as e:
            raise Exception(e)

    @loguru.logger.catch() #for logging
    def post(self):
        '''
            This method is used to create new data into db
        '''
        try:
            logger.debug('PostRoutes : {}'.format(request.method),request)

            name = request.json["name"]
            content = request.json["content"]

            newPost = Posts(name=name, content=content)
            db.session.add(newPost)
            db.session.commit()

            return (SinglePosts.jsonify(newPost))
        except Exception as e:
            raise Exception(e)

from time import time
from flask import Blueprint, jsonify, request, render_template, url_for, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from flask_restful import Api, Resource
from src.models import db, User, SingleSerializedUser, Posts, SinglePosts, MultiplePosts
from src.services.mailers import SendMail, send_password_reset_email, SendResetMail
from src.services.textmsg import SendOtp
import random
import jwt
import os
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.environ.get('SECRET_KEY')

#email validation
from src.checks.valid_email import verify_email
#otp validation
from src.checks.valid_otp import verify_otp
#password validation
from src.checks.valid_password import verify_password
#token validation
from src.midlleware.token_midleware import verify_token

app = Blueprint('app',__name__)
api = Api(app)


class Home(Resource):
    def get(self):
        return {"msg":"Hello, world!"}

class Signup(Resource):
    def post(self):
        if 'username' not in request.json:
            return {"msg":"Username not found"}
        if 'password' not in request.json:
            return {"msg":"Password not found"}
        if 'email' not in request.json:
            return {"msg":"Email not found"}
        
        username = request.json['username']
        password = request.json['password']
        if verify_password(password)==False:
            return {"Password Verification failed":"Password should be 6-12 characters long and should contain atleast one upper case character, one lower case character and one special character(!,@,#,&) and should not contain empty spaces"}

        hashed_password=generate_password_hash(password)
        email = request.json['email']
        if verify_email(email)==False:
            return jsonify({"Email Error":"Invalid email address"})

        contact_number = request.json['contact_number']
        if User.query.filter_by(username=username).count():
            return jsonify({'Username error':'username already registered'})
        else:
            newUser = User(username=username,password=hashed_password,email=email,contact_number=contact_number)
            try:
                SendMail(email,"Your account has been created")
                db.session.add(newUser)
                db.session.commit()
                
                return SingleSerializedUser.jsonify(newUser)
            except Exception as e:
                print(e)
                return jsonify({'msg':'Unable to create User'})

class Login(Resource):
    def post(self):
        if 'email' not in request.json:
            return {"Email error":"Email not found"}
        if 'password' not in request.json:
            return {"Password error":"Password not found"}
        
        email = request.json['email']
        password = request.json['password']

        if verify_password(password)==False:
            return {"Password Verification failed":"Password should be 6-12 characters long and should contain atleast one upper case character, one lower case character and one special character(!,@,#,&) and should not contain empty spaces"}
        
        if User.query.filter_by(email=email).count():
            targetUser = User.query.filter_by(email=email).first()
            if check_password_hash(targetUser.password,password)==True:
                if targetUser.isVerified==False:
                    one_time_password = random.randint(1000,9999)
                    targetUser.otp = one_time_password
                    targetUser.otp_released = time()
                    db.session.commit()
                    SendOtp(one_time_password,targetUser.contact_number)
                    SendMail(targetUser.email,'Your One time password is {}'.format(one_time_password))
                    # return jsonify({'Otp message':'Otp sent successfully on your registered mobile number and email and is valid for 5 minutes .Please provide the same.'})

                    login_token = jwt.encode(
                        {
                            'email' : targetUser.email,
                            'exp': time() + 300
                        },'{}'.format(SECRET_KEY, algorithms="HS256")
                    )

                    return jsonify({
                        'Otp message':'Otp sent successfully on your registered mobile number and email and is valid for 5 minutes .Please provide the same.',
                        'token': login_token
                    })

                else:
                    return jsonify({'msg':"User Logged in"})
            else:
                return jsonify({'msg':'Wrong Password'})
        else:
            return jsonify({'msg':'User not registered'})
        # else: 
            

class LoginWithOtp(Resource):
    def post(self):
        if 'otp' not in request.json:
            return jsonify({'msg':'Otp not provided'})
        if 'email' not in request.json:
            return {"msg":"Email not found"}
        email = request.json['email']
        otp_provided = request.json['otp']
        if User.query.filter_by(email=email).count():
            targetUser = User.query.filter_by(email=email).first()
            if verify_otp(targetUser, otp_provided)==True:
                targetUser.isVerified=True
                targetUser.otp_released=None
                db.session.commit()
                return jsonify({'msg':'OTP verified successfully || User logged in'})
            else:
                return jsonify({'msg':'Invalid otp provided or Otp Expired'})
        else:
            return jsonify({'msg':'User not found'})

class ChangeVerifiedStatus(Resource):
    def post(self): 
        if 'email' not in request.json:
            return {"msg":"Email not found"}
        email=request.json['email']
        targetUser = User.query.filter_by(email=email).first()
        targetUser.isVerified = False
        db.session.commit()

        return jsonify({'msg':'status changed to False'})

class ResetPasswordRequest(Resource):
    def post(self):
        if 'email' not in request.json:
            return {"msg":"Email not found"}
        email = request.json['email']
        user = User.query.filter_by(email=email).first()
        if user:
            send_password_reset_email(user)
            return jsonify({'msg':'A link to reset password has been sent to your registered email id. '})
        else:
            return jsonify({'msg':'User not found'})


class ResetPassword(Resource):
    def post(self,token):
        user = User.verify_reset_password_token(token)
        if not user:
            return jsonify({'msg':'No user found'})
        if request.method == 'POST':
            password = request.form['password']
            user.password = generate_password_hash(password)
            db.session.commit()
            return "Password Changed"
        elif request.method == 'GET':
            return render_template('reset.html')
    def get(self,token):
        user = User.verify_reset_password_token(token)
        if not user:
            return jsonify({'error':'Token expired or invalid user'})
        return make_response(render_template('reset.html'))

class PostRoutes(Resource):
    decorators = [verify_token]
    def get(self,*args, **kwargs):
        all_posts = Posts.query.all()
        return MultiplePosts.jsonify(all_posts)

    def post(self):
        name = request.json['name']
        content = request.json['content']

        newPost = Posts(name=name,content=content)
        db.session.add(newPost)
        db.session.commit()

        return SinglePosts.jsonify(newPost)


#ALl routes

api.add_resource(Home,'/')
api.add_resource(Signup,'/signup')
api.add_resource(Login,'/login')
api.add_resource(LoginWithOtp,'/OtpLogin')
api.add_resource(ChangeVerifiedStatus,'/change_status')
api.add_resource(ResetPasswordRequest,'/reset_password_request')
api.add_resource(ResetPassword,'/reset_password/<token>')
api.add_resource(PostRoutes,'/posts')
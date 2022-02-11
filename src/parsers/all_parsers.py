from flask_restx import reqparse

signup_parser = reqparse.RequestParser()

signup_parser.add_argument('username',type=str,required=True)
signup_parser.add_argument('password',type=str,required=True)
signup_parser.add_argument('contact_number',type=str,required=True)
signup_parser.add_argument('email',type=str,required=True)



login_parser = reqparse.RequestParser()

login_parser.add_argument('email',type=str,required=True)
login_parser.add_argument('password',type=str,required=True)


otp_parser = reqparse.RequestParser()
otp_parser.add_argument('email',type=str,required=True)
otp_parser.add_argument('otp',type=str,required=True)
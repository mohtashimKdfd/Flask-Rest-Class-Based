from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from flask import render_template
from dotenv import load_dotenv
import os

load_dotenv()
FROM_EMAIL = os.getenv('FROM_EMAIL')
SENDGRID_KEY = os.getenv('SENDGRID_KEY')

def SendMail(email,msg):
    message = Mail(
        from_email='mohtashim.kamran@unthinkable.co',
        to_emails=email,
        subject='Important mail for testing purpose',
        html_content='<strong>{} . This mail is sent via sendgrid</strong>'.format(msg))
    try:
        sg = SendGridAPIClient('{}'.format(SENDGRID_KEY))
        response = sg.send(message)
        print(response.status_code)
        print(response.body)
        print(response.headers)
    except Exception as e:
        print(e)


#Specific for emailing password reset
def SendResetMail(email,body):
    message = Mail(
        from_email='{}'.format(FROM_EMAIL),
        to_emails=email,
        subject='Important mail for testing purpose',
        html_content=body)
    try:
        sg = SendGridAPIClient('{}'.format(SENDGRID_KEY))
        response = sg.send(message)
        print(response.status_code)
        print(response.body)
        print(response.headers)
    except Exception as e:
        print(e)

def send_password_reset_email(user):
    token = user.get_reset_password_token()
    SendResetMail(user.email, render_template('reset_password.html',user=user,token=token))
from time import time

def verify_otp(user,otp_given):
    curr_time = time()
    otp_released_time = user.otp_released
    user_otp = user.otp 

    if curr_time - otp_released_time > 300:
        return False
    elif user_otp != otp_given:
        return False
    return True
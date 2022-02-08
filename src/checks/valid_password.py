def verify_password(password):
    special = ['&','@',"#",'!']
    num=upper=lower=spec=False
    for i in password:
        if ord(i)>=65 and ord(i)<=90:
            upper=True
        if ord(i)>=97 and ord(i)<=122:
            lower=True
        if i.isnumeric():
            num=True
        if i in special:
            spec=True
        
    if num and upper and lower and spec and " " not in password and len(password)>=6 and len(password)<=12:
        return True
    return False
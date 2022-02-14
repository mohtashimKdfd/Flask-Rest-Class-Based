from src.models import User


def isUniqueUser(username,email):
    if User.query.filter_by(username=username).count():
        return False
    if User.query.filter_by(email=email).count():
        return False
    return True

def isRegisteredUser(email):
    if User.query.filter_by(email=email).count():
        return True
    return False
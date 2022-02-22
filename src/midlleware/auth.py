from functools import wraps,update_wrapper
from src.config.error_codes import error
def authorize(roles=()):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if 'admin' not in roles:
                return {
                    'status': error['403'],
                    'msg': 'Not admin'
                }
            else: return f(*args, **kwargs)
        return update_wrapper(wrapper,f)
    return decorator

    
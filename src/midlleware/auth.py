from functools import wraps,update_wrapper
def authorize(roles=()):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if 'admin' not in roles:
                return {'msg':'Not admin'}
            else: return f(*args, **kwargs)
        return update_wrapper(wrapper,f)
    return decorator

    
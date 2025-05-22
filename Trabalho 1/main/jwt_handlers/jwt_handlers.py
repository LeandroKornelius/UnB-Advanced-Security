import jwt
import datetime

HMAC_SECRET = 'leozismo'

def generate_token(email, method):
    payload = {
        'sub': email,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
    }
    if method == 'HS256':
        return jwt.encode(payload, HMAC_SECRET, algorithm='HS256')
    elif method in ['RS256', 'PS256']:
        with open('../keys/private.pem', 'rb') as f:
            private_key = f.read()
        return jwt.encode(payload, private_key, algorithm=method)
    else:
        raise ValueError('Unsupported token generate algorithm')

def validate_token(token, method):
    try:
        if method == 'HS256':
            return jwt.decode(token, HMAC_SECRET, algorithms=['HS256'])
        elif method in ['RS256', 'PS256']:
            with open('../keys/public.pem', 'rb') as f:
                public_key = f.read()
            return jwt.decode(token, public_key, algorithms=[method])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
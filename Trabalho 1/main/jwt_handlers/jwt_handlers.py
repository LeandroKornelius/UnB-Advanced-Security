import jwt
import datetime

HMAC_SECRET = 'leozismo'

class TokenMissingError(Exception): pass
class TokenExpiredError(Exception): pass
class TokenInvalidError(Exception): pass
class UnsupportedAlgorithmError(Exception): pass

def generate_token(email, method):
    payload = {
        'sub': email,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
    }
    if method == 'HS256':
        return jwt.encode(payload, HMAC_SECRET, algorithm=method)
    elif method == 'RS256':
        private_key = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAwhvqCC+37A+UXgcvDl+7nbVjDI3QErdZBkI1VypVBMkKKWHM\nNLMdHk0bIKL+1aDYTRRsCKBy9ZmSSX1pwQlO/3+gRs/MWG27gdRNtf57uLk1+lQI\n6hBDozuyBR0YayQDIx6VsmpBn3Y8LS13p4pTBvirlsdX+jXrbOEaQphn0OdQo0WD\noOwwsPCNCKoIMbUOtUCowvjesFXlWkwG1zeMzlD1aDDS478PDZdckPjT96ICzqe4\nO1Ok6fRGnor2UTmuPy0f1tI0F7Ol5DHAD6pZbkhB70aTBuWDGLDR0iLenzyQecmD\n4aU19r1XC9AHsVbQzxHrP8FveZGlV/nJOBJwFwIDAQABAoIBAFCVFBA39yvJv/dV\nFiTqe1HahnckvFe4w/2EKO65xTfKWiyZzBOotBLrQbLH1/FJ5+H/82WVboQlMATQ\nSsH3olMRYbFj/NpNG8WnJGfEcQpb4Vu93UGGZP3z/1B+Jq/78E15Gf5KfFm91PeQ\nY5crJpLDU0CyGwTls4ms3aD98kNXuxhCGVbje5lCARizNKfm/+2qsnTYfKnAzN+n\nnm0WCjcHmvGYO8kGHWbFWMWvIlkoZ5YubSX2raNeg+YdMJUHz2ej1ocfW0A8/tmL\nwtFoBSuBe1Z2ykhX4t6mRHp0airhyc+MO0bIlW61vU/cPGPos16PoS7/V08S7ZED\nX64rkyECgYEA4iqeJZqny/PjOcYRuVOHBU9nEbsr2VJIf34/I9hta/mRq8hPxOdD\n/7ES/ZTZynTMnOdKht19Fi73Sf28NYE83y5WjGJV/JNj5uq2mLR7t2R0ZV8uK8tU\n4RR6b2bHBbhVLXZ9gqWtu9bWtsxWOkG1bs0iONgD3k5oZCXp+IWuklECgYEA27bA\n7UW+iBeB/2z4x1p/0wY+whBOtIUiZy6YCAOv/HtqppsUJM+W9GeaiMpPHlwDUWxr\n4xr6GbJSHrspkMtkX5bL9e7+9zBguqG5SiQVIzuues9Jio3ZHG1N2aNrr87+wMiB\nxX6Cyi0x1asmsmIBO7MdP/tSNB2ebr8qM6/6mecCgYBA82ZJfFm1+8uEuvo6E9/R\nyZTbBbq5BaVmX9Y4MB50hM6t26/050mi87J1err1Jofgg5fmlVMn/MLtz92uK/hU\nS9V1KYRyLc3h8gQQZLym1UWMG0KCNzmgDiZ/Oa/sV5y2mrG+xF/ZcwBkrNgSkO5O\n7MBoPLkXrcLTCARiZ9nTkQKBgQCsaBGnnkzOObQWnIny1L7s9j+UxHseCEJguR0v\nXMVh1+5uYc5CvGp1yj5nDGldJ1KrN+rIwMh0FYt+9dq99fwDTi8qAqoridi9Wl4t\nIXc8uH5HfBT3FivBtLucBjJgOIuK90ttj8JNp30tbynkXCcfk4NmS23L21oRCQyy\nlmqNDQKBgQDRvzEB26isJBr7/fwS0QbuIlgzEZ9T3ZkrGTFQNfUJZWcUllYI0ptv\ny7ShHOqyvjsC3LPrKGyEjeufaM5J8EFrqwtx6UB/tkGJ2bmd1YwOWFHvfHgHCZLP\n34ZNURCvxRV9ZojS1zmDRBJrSo7+/K0t28hXbiaTOjJA18XAyyWmGg==\n-----END RSA PRIVATE KEY-----\n"
        return jwt.encode(payload, private_key, algorithm=method)
    elif method == 'PS256':
        private_key = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEAuNhCS6bodtd+PvKqNj+tYZYqTNMDkf0rcptgHhecSsMP9Vay\n+6NvJk1tC+IajPaE4yRJVY4jFqEt3A0MJ9sKe5mWDYFmzW/L6VzQvQ+0nrMc1YTE\nDpOf7BQhlW5W0mDj5SwSR50Lxg/acb+SMWq6zmhuAoLRapH17K2RWONA2vr2frox\nJ6N9TGtrQHygDb0p9D6jPnXEe4y+zBuj6o0bCkJgCVNM+CU19xBepj5caetYV28/\n49yl5XPi93n1ATU+7aGAKxuvjudODuHhF/UsZScMFSHeZW367eQldTB2w9uoIIzW\nO46tKimr21zYifMimjwnBQ/PLDqc7HqY0Y/rLQIDAQABAoIBAAdu0CD7/Iu61/LE\nDfV8fgZXOYA5WVgSLCBsVbh1Y+2FsStBFJVrLwRanLCbo6GuJWMqNGC3ryWGebJI\nPAg7lfepEhBHodClAY1yvq9mOvHJa2Fn+KegEWWMMbAxQwCBW5NS6waXhBUE0i3n\ncYOB3TKA9IYuqH52kW22VQqT/imlWEb28pJJT49YfggmOOtAkrKerokO53lAfrJA\ntm8lYvxXnfnuYh7zI835RpZJ1PeaYrMqyAwT+StD9hPKGWGpN1gCJijjcK0aapvq\nMLET/JxMxxcLsINOeLtGhMKawmET3J/esJTumOE2L77MFG83rlCPbsSfLdSAI2WD\nSe3Q2ikCgYEA7JzmVrPh7G/oILLzIfk8GHFACRTtlE5SDEpFq+ARMprfcBXpkl+Q\naWqQ3vuSH7oiAQKlvo3We6XXohCMMDU2DyMaXiQMk73R83fMwbFnFcqFhbzx2zpm\nj/neHIViEi/N69SHPxl+vnUTfeVZptibNGS+ch3Ubawt3wCaWr+IdAcCgYEAx/19\ns5ryq2oTQCD5GfIqW73LAUly5RqENLvKHZ2z+mZ0pp7dc5449aDsHPLXLl1YC3mO\nlZZk+8Jh5yrpHyljiIYwh/1y0WsbungMlH6lG9JigcN8R2Tk9hWT7DQL0fm0dYoQ\njkwr/gJv6PW0piLsR0vsQQpm/F/ucZolVPQIoisCgYA5XXzWznvax/LeYqRhuzxf\nrK1axlEnYKmxwxwLJKLmwvejBB0B2Nt5Q1XmSdXOjWELH6oxfc/fYIDcEOj8ExqN\nJvSQmGrYMvBA9+2TlEAq31Pp7boxbYJKK8k23vu87wwcvgUgPj0lTdsw7bcDpYZT\neI1Xu3WyNUlVxJ6nm8IoZwKBgG6YPjVekKg+htrF4Tt58fa95E+X4JPVsBrBZqou\nFeN5WTTzUZ+odfNPxILVwC2BrTjbRgBvJPUcr6t4zWZQKxzKqHfrrt0kkDb0QHC2\nAHR8ScFc65NHtl5n3F+ZAJhjsGn3qeQnN4TGsEBx8C6XzXY4BDSLnhweqOvlxJNQ\nSJ31AoGAX/UN5xR6PlCgPw5HWfGd7+4sArkjA36DAXvrAgW/6/mxZZzoGA1swYdZ\nq2uGp38UEKkxKTrhR4J6eR5DsLAfl/KQBbNC42vqZwe9YrS4hNQFR14GwlyJhdLx\nKQD/JzHwNQN5+o+hy0lJavTw9NwAAb1ZzTgvq6fPwEG0b9hn0SI=\n-----END RSA PRIVATE KEY-----\n"
        return jwt.encode(payload, private_key, algorithm=method)
    else:
        raise ValueError('Unsupported token generate algorithm')

def validate_token(token, method):
    if not token:
        raise TokenMissingError('Missing token')
    try:
        if method == 'HS256':
            return jwt.decode(token, HMAC_SECRET, algorithms=['HS256'])
        elif method == 'RS256':
            public_key = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwhvqCC+37A+UXgcvDl+7\nnbVjDI3QErdZBkI1VypVBMkKKWHMNLMdHk0bIKL+1aDYTRRsCKBy9ZmSSX1pwQlO\n/3+gRs/MWG27gdRNtf57uLk1+lQI6hBDozuyBR0YayQDIx6VsmpBn3Y8LS13p4pT\nBvirlsdX+jXrbOEaQphn0OdQo0WDoOwwsPCNCKoIMbUOtUCowvjesFXlWkwG1zeM\nzlD1aDDS478PDZdckPjT96ICzqe4O1Ok6fRGnor2UTmuPy0f1tI0F7Ol5DHAD6pZ\nbkhB70aTBuWDGLDR0iLenzyQecmD4aU19r1XC9AHsVbQzxHrP8FveZGlV/nJOBJw\nFwIDAQAB\n-----END PUBLIC KEY-----\n"
            return jwt.decode(token, public_key, algorithms=[method])
        elif method == 'PS256':
            public_key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuNhCS6bodtd+PvKqNj+t\nYZYqTNMDkf0rcptgHhecSsMP9Vay+6NvJk1tC+IajPaE4yRJVY4jFqEt3A0MJ9sK\ne5mWDYFmzW/L6VzQvQ+0nrMc1YTEDpOf7BQhlW5W0mDj5SwSR50Lxg/acb+SMWq6\nzmhuAoLRapH17K2RWONA2vr2froxJ6N9TGtrQHygDb0p9D6jPnXEe4y+zBuj6o0b\nCkJgCVNM+CU19xBepj5caetYV28/49yl5XPi93n1ATU+7aGAKxuvjudODuHhF/Us\nZScMFSHeZW367eQldTB2w9uoIIzWO46tKimr21zYifMimjwnBQ/PLDqc7HqY0Y/r\nLQIDAQAB\n-----END PUBLIC KEY-----\n"
            return jwt.decode(token, public_key, algorithms=[method])
        else:
            raise UnsupportedAlgorithmError('Unsupported token validation algorithm')
    except jwt.ExpiredSignatureError:
        raise TokenExpiredError('Token has expired')
    except jwt.InvalidTokenError:
        raise TokenInvalidError('Token is invalid')
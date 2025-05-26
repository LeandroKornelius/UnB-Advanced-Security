import time
import jwt
import requests

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CERT_PATH = os.path.join(BASE_DIR, 'cert.pem')


AUTH_URLS = {
    'RS256': 'https://localhost:3333/login/rs',
    'PS256': 'https://localhost:3333/login/ps',
    'HS256': 'https://localhost:3333/login/hs',
}

DATA_URLS = {
    'RS256': 'https://localhost:3000/users/rs',
    'PS256': 'https://localhost:3000/users/ps',
    'HS256': 'https://localhost:3000/users/hs',
    'sign-up': 'https://localhost:3000/users/sign-up'
}

SHARED_SECRET = 'leozismo'

def simulate_invalid_signature(token):
    parts = token.split(".")
    corrupted = parts[2][::-1]
    return ".".join(parts[:2] + [corrupted])

def simulate_expired_token(email, method):
    payload = {
        'sub': email,
        'exp': int(time.time() - 61)
    }

    if method == 'HS256':
        return jwt.encode(payload, SHARED_SECRET, algorithm=method)
    elif method == 'RS256':
        private_key = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAwhvqCC+37A+UXgcvDl+7nbVjDI3QErdZBkI1VypVBMkKKWHM\nNLMdHk0bIKL+1aDYTRRsCKBy9ZmSSX1pwQlO/3+gRs/MWG27gdRNtf57uLk1+lQI\n6hBDozuyBR0YayQDIx6VsmpBn3Y8LS13p4pTBvirlsdX+jXrbOEaQphn0OdQo0WD\noOwwsPCNCKoIMbUOtUCowvjesFXlWkwG1zeMzlD1aDDS478PDZdckPjT96ICzqe4\nO1Ok6fRGnor2UTmuPy0f1tI0F7Ol5DHAD6pZbkhB70aTBuWDGLDR0iLenzyQecmD\n4aU19r1XC9AHsVbQzxHrP8FveZGlV/nJOBJwFwIDAQABAoIBAFCVFBA39yvJv/dV\nFiTqe1HahnckvFe4w/2EKO65xTfKWiyZzBOotBLrQbLH1/FJ5+H/82WVboQlMATQ\nSsH3olMRYbFj/NpNG8WnJGfEcQpb4Vu93UGGZP3z/1B+Jq/78E15Gf5KfFm91PeQ\nY5crJpLDU0CyGwTls4ms3aD98kNXuxhCGVbje5lCARizNKfm/+2qsnTYfKnAzN+n\nnm0WCjcHmvGYO8kGHWbFWMWvIlkoZ5YubSX2raNeg+YdMJUHz2ej1ocfW0A8/tmL\nwtFoBSuBe1Z2ykhX4t6mRHp0airhyc+MO0bIlW61vU/cPGPos16PoS7/V08S7ZED\nX64rkyECgYEA4iqeJZqny/PjOcYRuVOHBU9nEbsr2VJIf34/I9hta/mRq8hPxOdD\n/7ES/ZTZynTMnOdKht19Fi73Sf28NYE83y5WjGJV/JNj5uq2mLR7t2R0ZV8uK8tU\n4RR6b2bHBbhVLXZ9gqWtu9bWtsxWOkG1bs0iONgD3k5oZCXp+IWuklECgYEA27bA\n7UW+iBeB/2z4x1p/0wY+whBOtIUiZy6YCAOv/HtqppsUJM+W9GeaiMpPHlwDUWxr\n4xr6GbJSHrspkMtkX5bL9e7+9zBguqG5SiQVIzuues9Jio3ZHG1N2aNrr87+wMiB\nxX6Cyi0x1asmsmIBO7MdP/tSNB2ebr8qM6/6mecCgYBA82ZJfFm1+8uEuvo6E9/R\nyZTbBbq5BaVmX9Y4MB50hM6t26/050mi87J1err1Jofgg5fmlVMn/MLtz92uK/hU\nS9V1KYRyLc3h8gQQZLym1UWMG0KCNzmgDiZ/Oa/sV5y2mrG+xF/ZcwBkrNgSkO5O\n7MBoPLkXrcLTCARiZ9nTkQKBgQCsaBGnnkzOObQWnIny1L7s9j+UxHseCEJguR0v\nXMVh1+5uYc5CvGp1yj5nDGldJ1KrN+rIwMh0FYt+9dq99fwDTi8qAqoridi9Wl4t\nIXc8uH5HfBT3FivBtLucBjJgOIuK90ttj8JNp30tbynkXCcfk4NmS23L21oRCQyy\nlmqNDQKBgQDRvzEB26isJBr7/fwS0QbuIlgzEZ9T3ZkrGTFQNfUJZWcUllYI0ptv\ny7ShHOqyvjsC3LPrKGyEjeufaM5J8EFrqwtx6UB/tkGJ2bmd1YwOWFHvfHgHCZLP\n34ZNURCvxRV9ZojS1zmDRBJrSo7+/K0t28hXbiaTOjJA18XAyyWmGg==\n-----END RSA PRIVATE KEY-----\n"
        return jwt.encode(payload, private_key, algorithm=method)
    elif method == 'PS256':
        private_key = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEAuNhCS6bodtd+PvKqNj+tYZYqTNMDkf0rcptgHhecSsMP9Vay\n+6NvJk1tC+IajPaE4yRJVY4jFqEt3A0MJ9sKe5mWDYFmzW/L6VzQvQ+0nrMc1YTE\nDpOf7BQhlW5W0mDj5SwSR50Lxg/acb+SMWq6zmhuAoLRapH17K2RWONA2vr2frox\nJ6N9TGtrQHygDb0p9D6jPnXEe4y+zBuj6o0bCkJgCVNM+CU19xBepj5caetYV28/\n49yl5XPi93n1ATU+7aGAKxuvjudODuHhF/UsZScMFSHeZW367eQldTB2w9uoIIzW\nO46tKimr21zYifMimjwnBQ/PLDqc7HqY0Y/rLQIDAQABAoIBAAdu0CD7/Iu61/LE\nDfV8fgZXOYA5WVgSLCBsVbh1Y+2FsStBFJVrLwRanLCbo6GuJWMqNGC3ryWGebJI\nPAg7lfepEhBHodClAY1yvq9mOvHJa2Fn+KegEWWMMbAxQwCBW5NS6waXhBUE0i3n\ncYOB3TKA9IYuqH52kW22VQqT/imlWEb28pJJT49YfggmOOtAkrKerokO53lAfrJA\ntm8lYvxXnfnuYh7zI835RpZJ1PeaYrMqyAwT+StD9hPKGWGpN1gCJijjcK0aapvq\nMLET/JxMxxcLsINOeLtGhMKawmET3J/esJTumOE2L77MFG83rlCPbsSfLdSAI2WD\nSe3Q2ikCgYEA7JzmVrPh7G/oILLzIfk8GHFACRTtlE5SDEpFq+ARMprfcBXpkl+Q\naWqQ3vuSH7oiAQKlvo3We6XXohCMMDU2DyMaXiQMk73R83fMwbFnFcqFhbzx2zpm\nj/neHIViEi/N69SHPxl+vnUTfeVZptibNGS+ch3Ubawt3wCaWr+IdAcCgYEAx/19\ns5ryq2oTQCD5GfIqW73LAUly5RqENLvKHZ2z+mZ0pp7dc5449aDsHPLXLl1YC3mO\nlZZk+8Jh5yrpHyljiIYwh/1y0WsbungMlH6lG9JigcN8R2Tk9hWT7DQL0fm0dYoQ\njkwr/gJv6PW0piLsR0vsQQpm/F/ucZolVPQIoisCgYA5XXzWznvax/LeYqRhuzxf\nrK1axlEnYKmxwxwLJKLmwvejBB0B2Nt5Q1XmSdXOjWELH6oxfc/fYIDcEOj8ExqN\nJvSQmGrYMvBA9+2TlEAq31Pp7boxbYJKK8k23vu87wwcvgUgPj0lTdsw7bcDpYZT\neI1Xu3WyNUlVxJ6nm8IoZwKBgG6YPjVekKg+htrF4Tt58fa95E+X4JPVsBrBZqou\nFeN5WTTzUZ+odfNPxILVwC2BrTjbRgBvJPUcr6t4zWZQKxzKqHfrrt0kkDb0QHC2\nAHR8ScFc65NHtl5n3F+ZAJhjsGn3qeQnN4TGsEBx8C6XzXY4BDSLnhweqOvlxJNQ\nSJ31AoGAX/UN5xR6PlCgPw5HWfGd7+4sArkjA36DAXvrAgW/6/mxZZzoGA1swYdZ\nq2uGp38UEKkxKTrhR4J6eR5DsLAfl/KQBbNC42vqZwe9YrS4hNQFR14GwlyJhdLx\nKQD/JzHwNQN5+o+hy0lJavTw9NwAAb1ZzTgvq6fPwEG0b9hn0SI=\n-----END RSA PRIVATE KEY-----\n"
        return jwt.encode(payload, private_key, algorithm=method)

def sign_up(email, password):
    payload = {
        'email': email,
        'password': password
    }

    response = requests.post(DATA_URLS['sign-up'], json=payload, verify=False)

    if response.status_code == 201:
        print(f'User {email} created successfully.')
    elif response.status_code == 409:
        print(f'User {email} already exists.')
    else:
        print(f'Failed to create user {email}: {response.status_code} - {response.text}')

def login(email, password, method):
    payload = {
        'email': email,
        'password': password
    }
    response = requests.post(AUTH_URLS[method], json=payload, verify=False)

    if response.status_code == 200:
        token = response.json().get("token")
        print(f'Token aquired by the auth api using {method}')
        return token
    else:
        print(f'Failed login due to {response.text}')
        return None

def get_user_emails(token, method, test_name=''):
    headers = {}
    if headers is not None:
        headers['Authorization'] = f'Bearer {token}'

    response = requests.get(DATA_URLS[method], headers=headers, verify=False)

    print(f'\n{test_name} for {method}')
    print(f'Status Code: {response.status_code}')
    try:
        print(f'Response: {response.json()}')
    except:
        print(f'Response: {response.text}')

    if response.status_code == 200:
        users_emails = response.json()
        print(f'User emails aquired using {method}:')
        for email in users_emails:
            print(f'- {email}')
    else:
        print(f'Failed to access data api due to {response.text}')

if __name__ == '__main__':
    email = 'cliente@teste.com'
    password = '123456'

    sign_up(email, password)

    for method in ['RS256', 'PS256', 'HS256']:
        print(f'\nIniciating tests with {method}...\n')

        token = login(email, password, method)

        if token:
            get_user_emails(token, method, 'Valid Token')

            get_user_emails(None, method, 'Missing Token')

            corrupted_token = simulate_invalid_signature(token)
            get_user_emails(corrupted_token, method, 'Invalid Token')

            expired_token = simulate_expired_token(email, method)
            get_user_emails(expired_token, method, 'Expired Token')

        else:
            print(f'Either user does not exist or the credentials are incorrect')
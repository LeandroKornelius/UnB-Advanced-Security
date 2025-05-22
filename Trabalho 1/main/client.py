import requests

AUTH_URL = ''
DATA_URL = ''

def login(email, password):
    payload = {
        'username': email,
        'password': password
    }
    response = requests.post(AUTH_URL, json=payload)

    if response.status_code == 200:
        token = response.json().get("token")
        print('Token aquired by the auth api')
        return token
    else:
        print(f'Failed login due to {response.text}')

def get_user_emails(token):
    headers = {
        'Authorization': f'Bearer {token}'
    }
    response = requests.get(DATA_URL, headers=headers)

    if response.status_code == 200:
        users_emails = response.json()
        print('User emails:')
        for email in users_emails:
            print(f'- {users_emails}')
    else:
        print(f'Failed to access data api due to {response.text}')

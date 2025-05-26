from http.server import HTTPServer, BaseHTTPRequestHandler
import json
from db import get_users_emails, add_user
from jwt_handlers.jwt_handlers import (
    validate_token,
    TokenMissingError,
    TokenExpiredError,
    TokenInvalidError,
    UnsupportedAlgorithmError
)

class ProtectedHandler(BaseHTTPRequestHandler):
    def do_GET(self):

        if self.path == '/users/rs':
            method = 'RS256'
        elif self.path == '/users/ps':
            method = 'PS256'
        elif self.path == '/users/hs':
            method = 'HS256'
        else:
            self.send_response(404)
            self.end_headers()
            return

        auth_header = self.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'Token not provided')
            return

        token = auth_header.split()[1]

        try:
            payload = validate_token(token, method)
        except TokenMissingError:
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'Token is missing.')
            return
        except TokenExpiredError:
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'Token has expired.')
            return
        except TokenInvalidError:
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b'Token is invalid.')
            return
        except UnsupportedAlgorithmError:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b'Unsupported token algorithm.')
            return
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b'Internal server error.')
            return

        emails = get_users_emails()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(emails).encode())

    def do_POST(self):
        if self.path == '/users/sign-up':

            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length)

            try:
                data = json.loads(body)
                email = data.get('email')
                password = data.get('password')
            except:
                self.send_response(400)
                self.end_headers()
                return

            if not email or not password:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'Email and password required')
                return

            if add_user(email, password):
                self.send_response(201)
                self.end_headers()
                self.wfile.write(b'User created')
            else:
                self.send_response(409)
                self.end_headers()
                self.wfile.write(b'User already exists')

        else:
            self.send_response(404)
            self.end_headers()
            return

if __name__ == '__main__':
    print('🛡️ Protected API running on http://localhost:3000')
    HTTPServer(('localhost', 3000), ProtectedHandler).serve_forever()
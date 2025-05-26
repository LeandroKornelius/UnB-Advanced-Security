import os
import ssl
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
from db import check_user_password
from jwt_handlers.jwt_handlers import generate_token

class AuthHandler(BaseHTTPRequestHandler):
    def do_POST(self):

        length = int(self.headers.get('Content-Length', 0))
        data = json.loads(self.rfile.read(length))
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'Email and password required.')
            return

        if not check_user_password(email, password):
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'Invalid credentials.')
            return

        if self.path == '/login/rs':
            method = 'RS256'
        elif self.path == '/login/ps':
            method = 'PS256'
        elif self.path == '/login/hs':
            method = 'HS256'
        else:
            self.send_response(404)
            self.end_headers()
            return

        token = generate_token(email, method)
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({'token': token}).encode())

if __name__ == '__main__':
    cert_path = os.path.join(os.path.dirname(__file__), '..', 'cert.pem')
    key_path = os.path.join(os.path.dirname(__file__), '..', 'key.pem')

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)

    server_address = ('localhost', 3333)
    httpd = HTTPServer(server_address, AuthHandler)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    print('🔐 Auth API running securely on https://localhost:3333')
    httpd.serve_forever()


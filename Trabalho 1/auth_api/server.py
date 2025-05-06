from http.server import HTTPServer
from handlers import AuthAPIHandler

HOST = 'localhost'
PORT = 3333

if __name__ == '__main__':
    server = HTTPServer((HOST, PORT), AuthAPIHandler)
    print(f'Server running on http://{HOST}:{PORT}')
    server.serve_forever()
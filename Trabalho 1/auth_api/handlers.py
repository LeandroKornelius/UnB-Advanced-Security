from http.server import BaseHTTPRequestHandler
import json

class AuthAPIHandler(BaseHTTPRequestHandler):

    def _set_headers(self, status=200, content_type='application/json'):
        self.send_response(status)
        self.send_header('Content-type', content_type)
        self.end_headers()

    def do_GET(self):
        if self.path == "/api/hello-world":
            self._set_headers()
            response = {'message': 'Hello World!'}
            self.wfile.write(json.dumps(response).encode('utf-8'))
        else:
            self._set_headers(404)
            self.wfile.write(json.dumps({'error': 'Not found'}).encode('utf-8'))
"""
A simple web server implementation with some features and issues to detect.
"""
import socket
import threading
import json
import logging
from urllib.parse import urlparse, parse_qs

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("simple_server")

class SimpleHTTPServer:
    def __init__(self, host="localhost", port=8080):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.routes = {}
        
    def route(self, path):
        """Decorator to register route handlers"""
        def decorator(handler):
            self.routes[path] = handler
            return handler
        return decorator
        
    def start(self):
        """Start the HTTP server"""
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        logger.info(f"Server started on {self.host}:{self.port}")
        
        try:
            while True:
                client, addr = self.socket.accept()
                logger.info(f"Client connected: {addr}")
                client_thread = threading.Thread(target=self.handle_client, args=(client,))
                client_thread.daemon = True
                client_thread.start()
        finally:
            self.socket.close()
            
    def handle_client(self, client_socket):
        """Handle client connection"""
        try:
            # Read HTTP request
            request = client_socket.recv(1024).decode('utf-8')
            if not request:
                return
                
            # Parse request
            request_line = request.split('\n')[0]
            method, path, protocol = request_line.split()
            
            # Extract query parameters
            url_parts = urlparse(path)
            path = url_parts.path
            query = parse_qs(url_parts.query)
            
            # Find and execute route handler
            if path in self.routes:
                response_body = self.routes[path](query)
                if isinstance(response_body, dict):
                    response_body = json.dumps(response_body)
            else:
                response_body = "404 Not Found"
                
            # Send response
            response = f"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {len(response_body)}\r\n\r\n{response_body}"
            client_socket.send(response.encode('utf-8'))
            
        except Exception as e:
            logger.error(f"Error handling client: {e}")
        finally:
            client_socket.close()

# Create server instance
server = SimpleHTTPServer()

@server.route("/hello")
def hello(params):
    name = params.get("name", ["World"])[0]
    return f"<h1>Hello, {name}!</h1>"

@server.route("/data")
def data(params):
    # Potential security issue: No input validation
    return {
        "status": "success",
        "data": params
    }

if __name__ == "__main__":
    server.start()
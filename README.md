#EgressBuster
Copyright 2015 TrustedSec - EgressBuster

Written by: David Kennedy (ReL1K)

Company: [TrustedSec](https://www.trustedsec.com)

DISCLAIMER: This is only for testing purposes and can only be used where strict consent has been given. Do not use this for illegal purposes period.

Please read the LICENSE for the licensing of EgressBuster. 

#Features

EgressBuster is a way to test the effectiveness of egress filtering for an individual area. When performing a penetration test, often times companies leverage egress filtering in order to prevent access to the outside Internet. Most companies have special exceptions and allow ports but they may be difficult to find.

There are two components to EgressBuster:

egressbuster<.py><.exe> - the egressbuster.py or egressbuster.exe can be run in Linux/OSX/Windows(EXE). This will check outbound ports to a location where you have egress_listener.py. Run this on the victim machine you want to check the ports on. You can also spawn an automatic command shell once a port is detected.

egressbuster_listener.py - this is the listener, this will automatically use IPTables to listen on all 65k ports for a connection. When a connection is allowed, it will notify you as well as spawn a shell if you specified the shell option.

### Bugs and enhancements

For bug reports or enhancements, please open an issue here https://github.com/trustedsec/egressbuster/issues

### Supported platforms

EgressBuster supports Windows, Linux, OSX, etc. Note that the egress_listener.py is only supported on Linux. Since we now support all 65k ports, it will require you to run it on Linux/OSX since we use iptables.

Overview
========

This package primary role is to install a server in the machine that host a cuckoo sandbox, which provides remote secure
access to the Cuckoo sandbox functionality. Also  this package installs a plugin to cuckoo reporting modules that send
the analysis result to the main system server.

Installation
------------
- Run setup.py -cuckoopath cuckoo_path -inetsimpath inetsimpath -host server_host -port server_port \
                -initserveraddr initserveraddr -initserverport initserverport
    if cuckoopath is not provided, default cuckoo path has the value  '/opt/cuckoo'
    if inetsimpath is not provided,default inetsimpath has the value '/opt/inetsim/'
    if host is not provided, default server host has the value 'localhost'
    if path is not provided, default server port has the value 5000
    if initserveraddr is not provided, default init server address has the value 'localhost'
    if initserverport is not provided, default init server port has the value 8000

Futures changes can be inserted manually into serrver.conf file.


System Requirements
-------------------
-The software of Virtual machine needs to be VirtualBox
-The name of virtual machine that used from Cuckoo Sandbox must be cuckoo1
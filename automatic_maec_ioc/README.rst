Overview
========
IoC Server is the system's core. Receives malware subjects, send them  to analyzers, receives analysis results and creates
IoCs in MAEC format. Finally it sends a copy of ioc in the client. This package also contains an init-server ,whose primary
role is to inform the IoC server about available analyzers.

Installation
------------
Run setup.py

-apath      [path]  path of cuckoo analysis results
-mpath       [path]  path of malware subjects direcory
-host       [addr]   IoC server address
-port       [port]   IoC server port
-iport       [port] init server port
-h       help

- if apath is not provided, default analysis path has the value  './analyis_hub'
- if mpath is not provided,default malwares directory has the value './malware_hub'
- if host is not provided, default IoC server host has the value 'localhost'
- if port is not provided, default server port has the value 10000
- if iport is not provided, default init server port has the value 8000

Futures changes can be inserted manually into serrver.conf file.

After the execution the directory tree should be have the following structure:

| sandbox/
| ├── common
| │   ├── configmanager.py
| │   ├── configmanager.pyc
| │   ├── __init__.py
| │   ├── __init__.pyc
| │   ├── logger.py
| │   └── logger.pyc
| ├── conf
| │   ├── log.conf
| │   └── server.conf
| ├── extensions
| │   ├── cuckoo_messenger.py
| │   └── __init__.py
| ├── __init__.py
| ├── log
| ├── malware_hub/
| ├── README.rst
| ├── remote_access_server.py
| ├── server_certificates/
| │
| └── setup.py

System Requirements
-------------------
- The software of Virtual machine needs to be VirtualBox
- The name of virtual machine that used from Cuckoo Sandbox must be cuckoo1
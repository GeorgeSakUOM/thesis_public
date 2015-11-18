Overview
========
IoC Server is the system core. Receives malware subjects, send them  to analyzers, receives analysis results and creates
IoCs in MAEC format. Finally it sends a copy of ioc in the client.

Installation
------------
- Run setup.py -path analysis_hub_path -host server_host -port server_port
    if path is not provided, default analysis result path has the value  'analysis_hub'
    if host is not provided, default server host has the value 'localhost'
    if path is not provided, default server port path has the value 10000

System Requirements
-------------------

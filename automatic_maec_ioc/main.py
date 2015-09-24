'''

@author: george
'''

import json, os, errno, logging, ConfigParser,sys
global FILENUMBER, DBFILENAME
from server.logger import Logger
from server.configmanager import ConfigurationManager

patth='../log'
pconf ='../conf'

if __name__ == '__main__':
    #print MAEC_Bundle.maecBundle
    
    config = ConfigParser.RawConfigParser()
    
    config.add_section('Server')
    config.set('Server', 'ANALYSIS_PATH', os.path.abspath(os.path.join(os.path.dirname(__file__),"../analysis_hub")))
    config.set('Server', 'FILENUMBER', '0')
    config.set('Server', 'DBFILENAME', 'cuckoo_results_')
    config.set('Server', 'ADDRESS', 'localhost')
    config.set('Server', 'PORT_NUMBER', '10000')
    # Writing our configuration file to 'example.cfg'
    with open(os.path.join(pconf,'server.conf'), 'w') as configfile:
        config.write(configfile)
        configfile.close()
    
    
    config.read('../conf/server.conf')
    
    print config.get('Server', 'analysis_path')
    t=1+ int(config.get('Server','port_number'))
    print(t)
    
    print ConfigurationManager.readServerConfig(variable='address')
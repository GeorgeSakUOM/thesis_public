'''

@author: george
'''

import json, os, errno, logging, ConfigParser,sys
global FILENUMBER, DBFILENAME
from logger import Logger
from configmanager import ConfigurationManager

patth='../log'
pconf ='../conf'
if __name__ == '__main__':
    #print MAEC_Bundle.maecBundle
    '''
    config = ConfigParser.RawConfigParser()
    
    config.add_section('Logging')
    config.set('Logging', 'LOG_PATH', os.path.abspath(os.path.join(os.path.dirname(__file__),"../log")))
    config.set('Logging', 'ERROR_FILENAME', 'error.log')
    config.set('Logging', 'WARNING_FILENAME', 'warning.log')
    config.set('Logging', 'DEBUG_FILENAME', 'debug.log')
    config.set('Logging', 'CRITICAL_FILENAME', 'critical_error.log')
    config.set('Logging', 'INFO_FILENAME', 'info.log')
    config.set('Logging', 'FORMAT', '"%(levelname)s:%(name)s:%(asctime)s:%(message)s"')
    config.set('Logging', 'DATEFORMAT', '%d-%m-%Y %I:%M:%S %p')
    # Writing our configuration file to 'example.cfg'
    with open(os.path.join(pconf,'log.conf'), 'w') as configfile:
        config.write(configfile)
        configfile.close()
    
    
    config.read('../conf/log.conf')
    
    print config.get('Logging', 'format')
    print config.get('Logging','debug_filename')
    print os.path.dirname(os.path.realpath(__file__))
    print os.path.abspath(os.path.join(os.path.dirname(__file__),"../conf"))
    
    print ConfigurationManager.readLogConfig(variable='log_path')
    
    '''
    
 

    try:
        num=1
        d=json.loads(num)
    except Exception, ioer:
        info= (str(ioer))
        logger = Logger()
        logger.errorLogging(msg =info)
        print(info)
        print('\nOK')
              
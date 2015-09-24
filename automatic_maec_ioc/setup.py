'''
@author: george
Initalize the configuration files adding system variables
'''
import os, ConfigParser
if __name__ == '__main__':
    try:
        config = ConfigParser.RawConfigParser()
        # Initialize configuration file of logs
        config.add_section('Logging')
        config.set('Logging', 'LOG_PATH', os.path.abspath(os.path.join(os.path.dirname(__file__),"log")))
        config.set('Logging', 'ERROR_FILENAME', 'error.log')
        config.set('Logging', 'WARNING_FILENAME', 'warning.log')
        config.set('Logging', 'DEBUG_FILENAME', 'debug.log')
        config.set('Logging', 'CRITICAL_FILENAME', 'critical_error.log')
        config.set('Logging', 'INFO_FILENAME', 'info.log')
        config.set('Logging', 'FORMAT', '%(levelname)s:%(name)s:%(asctime)s:%(message)s')
        config.set('Logging', 'DATEFORMAT', '%d-%m-%Y %I:%M:%S %p')
    
        with open(os.path.abspath(os.path.join(os.path.dirname(__file__),"conf",'log.conf')), 'w') as configfile:
            config.write(configfile)
            configfile.close()
        print('Configuration Completed successfully')
    except Exception, e :
        print e
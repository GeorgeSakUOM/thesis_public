'''
@author: george
Initalize the configuration files adding system variables
'''
import os, ConfigParser
if __name__ == '__main__':
    try:
        config = ConfigParser.RawConfigParser()
        # Initialize configuration file of logs
        print('Initialize configuration file of logs')
        config.add_section('Logging')
        config.set('Logging', 'LOG_PATH', os.path.abspath(os.path.join(os.path.dirname(__file__),"log")))
        config.set('Logging', 'ERROR_FILENAME', 'error.log')
        config.set('Logging', 'WARNING_FILENAME', 'warning.log')
        config.set('Logging', 'DEBUG_FILENAME', 'debug.log')
        config.set('Logging', 'CRITICAL_FILENAME', 'critical_error.log')
        config.set('Logging', 'INFO_FILENAME', 'info.log')
        config.set('Logging', 'FORMAT', '%(levelname)s:%(name)s:%(asctime)s:%(message)s')
        config.set('Logging', 'DATEFORMAT', '%d-%m-%Y %I:%M:%S %p') 
        # Writing configuration file to 'log.conf'
        print("Writing configuration file to 'log.conf'")
        with open(os.path.abspath(os.path.join(os.path.dirname(__file__),'conf','log.conf')), 'w') as configfile:
            config.write(configfile)
            configfile.close()
        config.remove_section('Logging')
        #Initialize configuration file of Server
        print('Initialize configuration file of Server')
        config.add_section('Server')
        config.set('Server', 'ANALYSIS_PATH', os.path.abspath(os.path.join(os.path.dirname(__file__),"analysis_hub")))
        config.set('Server', 'FILENUMBER', '0')
        config.set('Server', 'DBFILENAME', 'cuckoo_results_')
        config.set('Server', 'ADDRESS', 'localhost')
        config.set('Server', 'PORT_NUMBER', '10000')
        # Writing configuration file to 'server.conf'
        print("Writing configuration file to 'server.conf'")        
        with open(os.path.abspath(os.path.join(os.path.dirname(__file__),'conf','server.conf')), 'w') as configfile:
            config.write(configfile)
            configfile.close()
        print('Configuration Completed successfully')
    except Exception, e :
        print e
'''
@author: george
'''
import ConfigParser ,os

class ConfigurationManager():
    '''
    Configuration Manager imports and manipulates all conf files
    '''
    
    def __init__(self):
        '''
        Constructor
        '''
        
        
    @staticmethod
    def readLogConfig(variable=None,filename='log.conf',section='Logging'):
        config = ConfigParser.RawConfigParser()
        pathConf =  os.path.abspath(os.path.join(os.path.dirname(__file__),"../conf"))
        file_path = os.path.join(pathConf,filename)
        config.read(file_path)
        var = config.get(section, variable)
        return var 
    
    @staticmethod
    def readServerConfig(variable=None,filename='server.conf',section='Server'):
        config = ConfigParser.RawConfigParser()
        pathConf =  os.path.abspath(os.path.join(os.path.dirname(__file__),"../conf"))
        file_path = os.path.join(pathConf,filename)
        config.read(file_path)
        var = config.get(section, variable)
        return var
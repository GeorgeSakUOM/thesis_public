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
    def readLogConfig(variable='',filepath='',filename='log.conf',section='Logging'):
        config = ConfigParser.RawConfigParser()
        pathConf =  os.path.abspath(os.path.join(os.path.dirname(__file__),"../conf"))
        filepath = os.path.join(pathConf,filename)
        config.read(filepath)
        var = config.get(section, variable)
        return var 
    
    @staticmethod
    def readServerConfig(variable='',filepath='',filename='server.conf',section='Server'):
        config = ConfigParser.RawConfigParser()
        pathConf =  os.path.abspath(os.path.join(os.path.dirname(__file__),"../conf"))
        filepath = os.path.join(pathConf,filename)
        config.read(filepath)
        var = config.get(section, variable)
        return var 
    
    @staticmethod
    def readmaecConfig(variable='',filepath='',filename='maec.conf',section='maec'):
        config = ConfigParser.RawConfigParser()
        pathConf =  os.path.abspath(os.path.join(os.path.dirname(__file__),"../conf"))
        filepath = os.path.join(pathConf,filename)
        config.read(filepath)
        var = config.get(section, variable)
        return var 
    
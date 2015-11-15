'''
@author: george

'''
import os, logging
from configmanager import ConfigurationManager

global LOG_PATH,ERROR_FILENAME,FORMAT,DATEFORMAT,WARNING_FILENAME,DEBUG_FILENAME,CRITICAL_FILENAME,INFO_FILENAME
 
LOG_PATH = ConfigurationManager.readLogConfig(variable = 'log_path')
ERROR_FILENAME = ConfigurationManager.readLogConfig(variable = 'error_filename')
WARNING_FILENAME = ConfigurationManager.readLogConfig(variable = 'warning_filename')
DEBUG_FILENAME = ConfigurationManager.readLogConfig(variable = 'debug_filename')
CRITICAL_FILENAME = ConfigurationManager.readLogConfig(variable = 'critical_filename')
INFO_FILENAME = ConfigurationManager.readLogConfig(variable = 'info_filename')
FORMAT =ConfigurationManager.readLogConfig(variable = 'format')
DATEFORMAT =ConfigurationManager.readLogConfig(variable = 'dateformat')

class Logger():
    '''
    Give tools for manipulation of log files 
    '''

    def __init__(self,logFormat = FORMAT,logDateFormat=DATEFORMAT,errorFilename=ERROR_FILENAME,warningFilename = WARNING_FILENAME,debugFilename=DEBUG_FILENAME,criticalFilename = CRITICAL_FILENAME,infoFilename=INFO_FILENAME,logPath=LOG_PATH):
        self.logFormat = logFormat
        self.log_date_format= logDateFormat
        self.errorFilePath = os.path.join(logPath,errorFilename)
        self.warningFilePath = os.path.join(logPath,warningFilename)
        self.debugFilePath = os.path.join(logPath,debugFilename)
        self.criticalFilePath = os.path.join(logPath,criticalFilename)
        self.infoFilePath = os.path.join(logPath,infoFilename)

    
    def errorLogging(self,msg,filepath=''):
        filepath=self.errorFilePath
        logging.basicConfig(format =self.logFormat,filename=filepath,level =logging.ERROR,datefmt=self.log_date_format)
        logging.error(msg)
    
    def warningLogging(self,msg,filepath=''): 
        filepath=self.warningFilePath
        logging.basicConfig(format =self.logFormat,filename=filepath,level =logging.WARNING,datefmt=self.log_date_format)
        logging.warn(msg)
    
    def debugLogging(self,msg,filepath=''): 
        filepath=self.debugFilePath
        logging.basicConfig(format =self.logFormat,filename=filepath,level =logging.DEBUG,datefmt=self.log_date_format)
        logging.debug(msg)
    
    def infoLogging(self,msg,filepath=''): 
        filepath=self.infoFilePath
        logging.basicConfig(format =self.logFormat,filename=filepath,level =logging.INFO,datefmt=self.log_date_format)
        logging.info(msg)
    
    def criticalLogging(self,msg,filepath=''): 
        filepath=self.warningFilePath
        logging.basicConfig(format =self.logFormat,filename=filepath,level =logging.CRITICAL,datefmt=self.log_date_format)
        logging.critical(msg)
    
    
    
    
    
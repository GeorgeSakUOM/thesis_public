'''

@author: george
'''

import json, os, errno, logging, ConfigParser,sys
global FILENUMBER, DBFILENAME
from common.logger import Logger
from common.configmanager import ConfigurationManager

patth='../log'
pconf ='../conf'

if __name__ == '__main__':
    
    print ConfigurationManager.readmaecConfig(variable='maec_path_bundles')
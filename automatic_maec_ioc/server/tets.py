__author__ = 'george'
from common.configmanager import ConfigurationManager
import json
SERVER_CERTIFICATE = ConfigurationManager.readServerConfig('server_certificate')
INIT_SERVER_ADDRESS = ConfigurationManager.readServerConfig('init_address')
INIT_SERVER_PORT = ConfigurationManager.readServerConfig('init_address')


a=["{1:'start',","2:'end'}"]



pt='/home/george/PycharmProjects/thesis_public/automatic_maec_ioc/analysis_hub/cuckoo_results'

fl = open(pt,'r')

res = json.load(fl)

print(res.keys())
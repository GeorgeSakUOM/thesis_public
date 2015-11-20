__author__ = 'george'
from common.configmanager import ConfigurationManager

SERVER_CERTIFICATE = ConfigurationManager.readServerConfig('server_certificate')
INIT_SERVER_ADDRESS = ConfigurationManager.readServerConfig('init_address')
INIT_SERVER_PORT = ConfigurationManager.readServerConfig('init_address')


print(SERVER_CERTIFICATE)
print(INIT_SERVER_ADDRESS)
print(INIT_SERVER_PORT)


import sys 
#from lib.cuckoo.common.abstracts import Report 
#from lib.cuckoo.common.abstracts import CuckooReportError
from socket import *


class CuckooMessenger :
    '''Cuckoo messenger takes the raw analysis results report and send it in maec_ioc_processor. 
    It will be placed inside Cuckoo's folder modules/reporting
    '''
    def __init__(self,results):
        self.results = results
        
    
    def run(self,results):
        #Create a TCP/IP socket
        sock = socket(AF_INET, SOCK_STREAM)

        #Connect the socket to the port where the maec -ioc server is listening
    
        server_address = ('localhost', 10000)
        print >>sys.stderr, 'connecting to %s port %s' % server_address
        try :
            sock.connect(server_address)
        except socket.error, msg:
            print('Connection Erro')
        
        try:
    
            # Send data
            message = self.results
            print >>sys.stderr, 'sending "%s"' % message
            sock.sendall(message)

            # Look for the response
            amount_received = 0
            amount_expected = len(message)
    
            while amount_received < amount_expected:
                data = sock.recv(16)
                amount_received += len(data)
                print >>sys.stderr, 'received "%s"' % data
        
        finally:
            print >>sys.stderr, 'closing socket'
            sock.close()




if __name__ == '__main__':
    msg = 'Hello messenger world'
    messenger = CuckooMessenger(msg)
    messenger.run(msg)
    
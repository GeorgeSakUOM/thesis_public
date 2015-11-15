import sys 
from lib.cuckoo.common.abstracts import Report 
from lib.cuckoo.common.abstracts import CuckooReportError
from socket import *
import json

class CuckooMessenger (Report):
    '''Cuckoo messenger takes the raw analysis results report and send it in maec_ioc_processor. 
    It will be placed inside Cuckoo's folder modules/reporting
    '''
    def run(self,results):
        #Create a TCP/IP socket
        sock = socket(AF_INET,SOCK_STREAM)

        #Connect the socket to the port where the maec -ioc server is listening    
        server_address = ('localhost', 10000)
        print >>sys.stderr, 'connecting to %s port %s' % server_address

        try :
            sock.connect(server_address)
        except socket.error, msg:
            raise CuckooReportError("Couldn't connect with the server: %s" % msg)
        
        try:
            # Send data
            message = json.dumps(results)
            sock.sendall(message)
            message_length = len(message)
            print('Sending "%s" bytes' % str(message_length) )
            # Checking that message has correctly sent.
            amount_received = 0
            amount_expected = message_length
            while amount_received < amount_expected:
                data = sock.recv(1024)
                amount_received += len(data)

            if amount_received == amount_expected:
                print >>sys.stderr, 'Data received'
            else:
                print >>sys.stderr, 'Missing data'    
        finally:
            print >>sys.stderr, 'closing socket'
            sock.close()
            
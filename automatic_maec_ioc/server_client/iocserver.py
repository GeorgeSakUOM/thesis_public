import  json
from socket import *

class IOCServer():
    '''
    IOCServer responses to request for IoCs and also it receives data from analysis and creates IoCs 
    '''


    def __init__(self, adress='localhost' ,port=10000):
        '''
        Constructor
        '''
        self.serveradress=(adress,port)
        
    def saveInFile(self,dbfilename='cuckoo_results',results=[]):
        dbfile = open(dbfilename,'w')
        data = json.load(''.join(results))
        json.dump(data,dbfile)
        dbfile.close()
        
    def start(self):
        sock = socket(AF_INET,SOCK_STREAM)
        print('Starting up on %s port %s '% self.serveradress)
        sock.bind(self.serveradress)
        sock.listen(1)
        chunks =[]
        messaselength =0
        while True:
            print('waiting for a connection') 
            connection, client_address = sock.accept()
            try:
                print >>sys.stderr, 'connection from', client_address
                # Receive the data in small chunks and retransmit it
                while True:
                    data = connection.recv(1024)
                    messaselength+=len(data)
                    if data:
                        connection.sendall(data)
                    else:
                        print >>sys.stderr, 'no more data from', client_address
                        break
                    chunks.append(data)
            finally:
                # Clean up the connection
                connection.close()
                print('Data received :',messaselength)
                self.saveInFile(results=chunks)
 
    
    
    
if __name__=='__main__':
    pass
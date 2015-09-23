import  json, os
from socket import *
from os import listdir
from os.path import isfile,join
from logger import Logger


#Define and initialize global variables // Global variables should be initialized from configuration file 
global FILENUMBER, DBFILENAME, JSONFILES
ANALYSIS_PATH ='../analysis_hub'
FILENUMBER = 0  
DBFILENAME ='cuckoo_results_'
JSONFILES = []


class IOCServer():
    '''
    IOCServer responses to request for IoCs and also it receives data from analysis and creates IoCs 
    '''

    def __init__(self, adress='localhost' ,port=10000):
        '''
        Constructor
        '''
        self.serveradress=(adress,port)
        self.logger =Logger()
        
    def saveInFile(self,dbfilename=DBFILENAME,filenumber=FILENUMBER,results=[]):
        '''
        Save received data to a unique json file. Checking first that data is dictionary. 
        '''
        try:
            filepath = os.path.join(ANALYSIS_PATH,dbfilename,str(filenumber))
            dbfile = open(filepath,'w')
            data = json.load(''.join(results))
            json.dump(data,dbfile)
            dbfile.close()
            FILENUMBER +=1
        except IOError, ioer :
            errorNum = ioer.errno
            errorCode = errno.errorcode[errorNum] 
            errorString= os.strerror(errorNum)
            errorFile = ioer.filename
            info=(errorNum,errorCode,errorString,errorFile)
            self.logger.errorLogging(msg=info) 
        except Exception, e :
            info = (str(e))
            self.logger.errorLogging(msg=info) 

    
    def loadFromFile(self,dbfilename):
        '''Loading the Report dictionary of cuckoo from a file that saved and recreate the dictionary'''
        try:
            dbfile = open(dbfilename,'r')
            data = dbfile.read()
            resultsDictionary = json.loads(data)
            dbfile.close()
        except IOError, ioer :
            errorNum = ioer.errno
            errorCode = errno.errorcode[errorNum] 
            errorString= os.strerror(errorNum)
            errorFile = ioer.filename
            info=(errorNum,errorCode,errorString,errorFile)
            self.logger.errorLogging(msg=info)  
        except Exception, e :
            info = (str(e))
            self.logger.errorLogging(msg=info) 
        return resultsDictionary
    
    def returnFile(self,analysisPath=ANALYSIS_PATH):
        '''Search the ANALYSIS PATH and return a list of files with the stored results'''
        try:
            onlyfiles = [ f for f in listdir(analysisPath) if isfile(join(analysisPath,f))]
            return onlyfiles     
        except Exception,e:
            info = (str(e))
            self.logger.errorLogging(msg=info) 
    
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
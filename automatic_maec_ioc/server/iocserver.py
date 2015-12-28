import  json, os, errno,SocketServer
from socket import *
from os import listdir
from os.path import isfile,join
from common.logger import Logger
from common.configmanager import ConfigurationManager


#Define and initialize global variables // Global variables should be initialized from configuration file 
ANALYSIS_PATH = ConfigurationManager.readServerConfig(variable='analysis_path')
FILENUMBER = int(ConfigurationManager.readServerConfig(variable='filenumber'))  
DBFILENAME = ConfigurationManager.readServerConfig(variable = 'dbfilename')
ADDRESS = ConfigurationManager.readServerConfig(variable = 'address')
PORT = int(ConfigurationManager.readServerConfig(variable='port'))
JSONFILES = []
server_address=(ADDRESS,PORT)
clients_port= int(ConfigurationManager.readServerConfig(variable='clients_port'))


class RequestHandler(SocketServer.BaseRequestHandler):

    def handle(self):
        pass


    def finish(self):
        pass

class IOCServer():

    def __init(self,console_queue,active, analyzers):
        global active_analyzers,console,analyzers_pool
        active_analyzers=active
        console = console_queue
        analyzers_pool=analyzers
        self.logger= Logger()

    def run(self):
        global console
        try:
            console.put("Starting up on %s port %s"% server_address)
            console.put(' ')
            server = SocketServer.ThreadingTCPServer(server_address,RequestHandler)
            server.serve_forever()
        except Exception,e:
            info=str(e)
            console.put(info)
            self.logger.errorLogging(info)



class IOColdServer():

    def __init__(self, adress=ADDRESS ,port=PORT):

        self.serveraddress=(adress,port)
        self.logger =Logger()

        
    def saveInFile(self,dbfilename=DBFILENAME,filenumber=FILENUMBER,results=None):
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
        resultsDictionary={}
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
        print('Starting up on %s port %s '% self.serveraddress)
        sock.bind(self.serveraddress)
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
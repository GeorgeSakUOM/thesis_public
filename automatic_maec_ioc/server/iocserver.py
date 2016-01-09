import  json, os, errno,SocketServer
from socket import *
from os import listdir
from os.path import isfile,join
from common.logger import Logger
from common.configmanager import ConfigurationManager
from ast import literal_eval
import ssl
import hashlib
#Define and initialize global variables // Global variables should be initialized from configuration file
ANALYSIS_PATH = ConfigurationManager.readServerConfig(variable='analysis_path')
ADDRESS = ConfigurationManager.readServerConfig(variable = 'address')
ANALYSIS_REPOSITORY=ConfigurationManager.readServerConfig(variable = 'maec_analysis_repository')
PORT = int(ConfigurationManager.readServerConfig(variable='port'))
server_address=(ADDRESS,PORT)
clients_port= int(ConfigurationManager.readServerConfig(variable='clients_port'))
SERVER_CERTIFICATE=ConfigurationManager.readServerConfig(variable='server_certificate')

class RequestHandler(SocketServer.BaseRequestHandler):

    def save_analysis_local(self,filename,analysis_results):
        try:
            xmlfilename= filename+".xml"
            filepath = os.path.join(ANALYSIS_REPOSITORY,xmlfilename)
            xmlfile =open(filepath,'w')
            xmlfile.write(analysis_results)
            xmlfile.close()
        except IOError, ioer :
            errorNum = ioer.errno
            errorCode = errno.errorcode[errorNum]
            errorString= os.strerror(errorNum)
            errorFile = ioer.filename
            info=(errorNum,errorCode,errorString,errorFile)
            Logger().errorLogging(msg=info)
        except Exception, e :
            info = (str(e))
            Logger().errorLogging(msg=info)

    def send_client_report(self,analysis_identity,maec_analysis):
        global console
        logger = Logger()
        cacert=None
        server_certificate=None
        server_key = None
        try:
            for cert in os.listdir(SERVER_CERTIFICATE):
                if all(x in cert for x in ['pem', 'server']):
                    server_certificate = os.path.join(SERVER_CERTIFICATE,cert)
                if 'ca' in cert:
                    cacert = os.path.join(SERVER_CERTIFICATE,cert)
                if 'key' in cert:
                    server_key =os.path.join(SERVER_CERTIFICATE,cert)
            sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            ssl_sock = ssl.wrap_socket(sock=sock,ca_certs=cacert,certfile=server_certificate,keyfile=server_key,cert_reqs=ssl.CERT_REQUIRED)
            ssl_sock.connect((analysis_identity[3],clients_port))
            console.put('Sending results to: '+str(analysis_identity[1]))
            maechash = hashlib.sha1(maec_analysis).hexdigest()
            client_analysis_identity=(maechash,analysis_identity[1],analysis_identity[5],analysis_identity[7],analysis_identity[2],analysis_identity[0])
            ssl_sock.send(str(client_analysis_identity))
            data = ssl_sock.recv()
            datatuple = literal_eval(data)
            console.put('Client message:'+str(datatuple[1]))
            if datatuple[0]=='ready':
                ssl_sock.sendall(maec_analysis)
                data = ssl_sock.recv()
                datatuple = literal_eval(data)
                console.put(datatuple[1])
                if not datatuple[0]:
                    pass
                    #TODO: What happens when client has not received the analysis results.
            ssl_sock.close()
        except Exception,e:
            info=str(e)
            console.put(info)
            logger.errorLogging(info)

    def system_update(self,analyzer_ip):
        global active_analyzers,console,analyzers_pool
        console.put('System updates analyzers pool')
        analysis_identity=active_analyzers.pop(analyzer_ip)
        analyzers_pool[analysis_identity[4]] = analyzer_ip
        return analysis_identity

    def manipulate_data(self,analyzer_ip,analysis_results):
        global console
        if analyzer_ip in active_analyzers.keys():
            analysis_identity=self.system_update(analyzer_ip)
            #TODO processsing the analysis results
            maec_analysis = 12
            self.send_client_report(analysis_identity,maec_analysis)
            console.put('Saving maec analysis in local repository')
            self.save_analysis_local(analysis_identity[0],maec_analysis)
            #info message :'Analysis:subject_name:client_id:client_ip:submission_time:analyzer_uuid'
            info='Analysis:'+analysis_identity[0]+':'+analysis_identity[1]+':'+analysis_identity[3]+':'+analysis_identity[2]+':'+analysis_identity[4]
            Logger().infoLogging(info)
        else:
            pass
            #TODO what the system does in case of lost identity

    def deal_with_client(self,constream):
        try:
            global console
            messaselength=0
            chunks=[]
            analyzer_ip=literal_eval(repr(constream.getpeername()))[0]
            while True:
                data = constream.recv(1024)
                messaselength+=len(data)
                if data:
                    constream.sendall(data)
                else:
                    break
                chunks.append(data)
            analysis_result = json.loads(''.join(chunks))
            self.manipulate_data(analyzer_ip,analysis_result)
        except Exception ,e:
            info=str(e)
            console.put(info)
            Logger().errorLogging(info)

    def handle(self):
        global console,active_analyzers,analyzers_pool
        console.put('Receiving analysis results...')
        try:
            constream = self.request
            self.deal_with_client(constream)
        except Exception,e:
            info=str(e)
            console.put(info)
            Logger().errorLogging(info)

    def finish(self):
        return SocketServer.BaseRequestHandler.finish(self)

class IOCServer():

    def __init__(self,console_queue,active, analyzers):
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

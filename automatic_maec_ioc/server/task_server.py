__author__ = 'george'
import SocketServer,socket,ssl,hashlib,os,fcntl
from ast import literal_eval
from common.configmanager import ConfigurationManager
from common.logger import Logger
from threading import Lock
import uuid

SERVER_CERTIFICATE = ConfigurationManager.readServerConfig('server_certificate')
SERVER_PORT = ConfigurationManager.readServerConfig('task_port')
SERVER_HOST=ConfigurationManager.readServerConfig('address')
server_address=(SERVER_HOST,int(SERVER_PORT))
ANALYZER_PORT=ConfigurationManager.readServerConfig('analyzer_port')


class TCPHandler(SocketServer.BaseRequestHandler):

    def get_analyzer(self,name,client_id,time,client_ip):
        global analyzers_pool,active_analyzers
        lock =Lock()
        analyzer=None
        try:
            lock.acquire()
            if analyzers_pool:
                analyzer= analyzers_pool.popitem()
                active_analyzers[analyzer[1]]=[name,client_id,time,client_ip,analyzer[0]]
            else:
                pass
                #what should be done if all analyzers have a task
        finally:
            lock.release()
        return analyzer

    def send_analysis_task(self,name,subject,hashtag,length,client_id,time,client_ip):
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
            analyzer = self.get_analyzer(name,client_id,time,client_ip)
            ssl_sock.connect((analyzer[1],ANALYZER_PORT))
            console.put("Sending identity")
            ssl_sock.send(str((uuid.uuid4(),name,'checksum',hashtag,length)))
            data = ssl_sock.recv()
            console.put(data)
            if data=='ready':
                ssl_sock.sendall(subject)
                data = ssl_sock.recv()
                console.put(data)
                data = ssl_sock.recv()
                console.put(data)
            ssl_sock.close()
            subjectinfo="Subject:%s|Hashvalue:%s|Length:%s|Client:%s|Client IP:%s|Analyzer:%s|Analyzer IP:%s "%(name,hashtag,length,client_id,client_ip,analyzer[0],analyzer[1])
            logger.infoLogging(subjectinfo)
        except Exception,e:
            info=str(e)
            console.put(info)
            logger.errorLogging(info)

    def manipulate_data(self,constream,data):
        global console
        datatuple = literal_eval(data)
        print(datatuple)
        if datatuple[0] =='identity':
            malware_length =datatuple[3]
            try:
                client_ip=literal_eval(repr(constream.getpeername()))[0]
                constream.send(str((True,'Analysis subject info has been received.')))
                chunks=[]
                datarecv=0
                while datarecv < malware_length:
                    chunk = constream.recv(min(malware_length -datarecv, 2048))
                    if chunk == b'':
                        raise RuntimeError("socket connection broken")
                    chunks.append(chunk)
                    datarecv = datarecv+ len(chunk)
                malware = b''.join(chunks)
                mal_check = hashlib.sha1(malware).hexdigest()

                if mal_check == datatuple[2]:
                    constream.sendall(str((True,'Received successfully')))
                    console.put('Sending subject for analysis...')
                    self.send_analysis_task(datatuple[5],malware,mal_check,malware_length,datatuple[1],datatuple[4],client_ip)
                else:
                    constream.sendall(str((False,'Try again')))

            except Exception,e:
                console.put(str(e))
                constream.send((False,'IoC Server fatal error. Try again later'))
        else:
            console.put("Client with identity %s has not yet addressed subject details"%datatuple[2])
            constream.send(str((False,'Client has not yet addressed subject details. Please run again the script ')))

        return False

    def deal_with_client(self,constream):
        data = constream.recv()
        while data:
            if not self.manipulate_data(constream, data):
                break
            data = constream.recv()


    def handle(self):
        server_certificate=None
        cacert = None
        server_key=None
        for cert in os.listdir(SERVER_CERTIFICATE):
            if all(x in cert for x in ['pem', 'server']):
                server_certificate = os.path.join(SERVER_CERTIFICATE,cert)
            if 'ca' in cert:
                cacert = os.path.join(SERVER_CERTIFICATE,cert)
            if 'key' in cert:
                server_key =os.path.join(SERVER_CERTIFICATE,cert)
        constream=ssl.wrap_socket(self.request,server_side=True,certfile=server_certificate,keyfile=server_key)
        try:
            self.deal_with_client(constream)
        finally:
            constream.shutdown(socket.SHUT_RDWR)
            constream.close()
        return

    def finish(self):
        return SocketServer.BaseRequestHandler.finish(self)

class TaskServer():
    def __init__(self,console_queue,analyzers,active_analyzers_dict):
        #update_analyzers_pool()
        self.logger =Logger()
        global analyzers_pool,console,active_analyzers
        analyzers_pool=analyzers
        console=console_queue
        active_analyzers=active_analyzers_dict

    def run(self):
        global console,analyzers_pool
        try:
            console.put("Starting up on %s port %s"% server_address)
            console.put('Available analyzers:')
            console.put(str(analyzers_pool))
            console.put(' ')
            server = SocketServer.ThreadingTCPServer(server_address,TCPHandler)
            server.serve_forever()
        except Exception,e:
            info=str(e)
            console.put(info)
            self.logger.errorLogging(info)
#Old code
def update_analyzers_pool():
    logger =Logger()
    try:
        global analyzers_pool
        analyzers = open('analyzers','r')
        fcntl.fcntl(analyzers,fcntl.LOCK_EX)
        data = analyzers.read()
        fcntl.fcntl(analyzers,fcntl.LOCK_UN)
        analyzers.close()
        analyzers_pool=literal_eval(data)
    except Exception,e:
        info=str(e)
        logger.errorLogging(info)


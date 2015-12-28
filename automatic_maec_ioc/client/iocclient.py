import os,socket,SocketServer,sys,ssl,time
from common.configmanager import ConfigurationManager
from common.logger import Logger
import hashlib
from ast import literal_eval
ANALYSIS_PATH=ConfigurationManager.readServerConfig('analysis_path')
MALWARE_PATH = ConfigurationManager.readServerConfig('malware_path')
IOC_SERVER_ADDR = ConfigurationManager.readServerConfig('ioc_address')
IOC_SERVER_PORT = int(ConfigurationManager.readServerConfig('ioc_port'))
SERVER_PORT= int(ConfigurationManager.readServerConfig('port'))
SERVER_ADDRESS=ConfigurationManager.readServerConfig('address')
ID = ConfigurationManager.readServerConfig('server_id')
CERTIFICATES_PATH = ConfigurationManager.readServerConfig('server_certificate')
ioc_server=(IOC_SERVER_ADDR,IOC_SERVER_PORT)
local_server=(SERVER_ADDRESS,SERVER_PORT)
malware_info=[]

class IOCClient(object):

    def __init__(self,filename):
        self.id =ID
        self.malware = filename
        for cert in os.listdir(CERTIFICATES_PATH):
            if all(x in cert for x in ['pem', 'client']):
                self.server_certificate = os.path.join(CERTIFICATES_PATH,cert)
            if 'ca' in cert:
                self.cacert = os.path.join(CERTIFICATES_PATH,cert)
            if 'key' in cert:
                self.server_key =os.path.join(CERTIFICATES_PATH,cert)

    def send_malware(self):
        flag=True
        try:
            malware_instance = open(self.malware,'rb').read()
            hashtag= hashlib.sha1(malware_instance).hexdigest()
            malware_length = len(malware_instance)
            sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            ssl_sock = ssl.wrap_socket(sock=sock,ca_certs=self.cacert,certfile=self.server_certificate,keyfile=self.server_key,cert_reqs=ssl.CERT_REQUIRED)
            ssl_sock.connect(ioc_server)
            print("Sending info for subject %s with hash value: %s and length: %d"%(self.malware,hashtag,malware_length))
            malware_info.append((hashtag,time.time()))
            ssl_sock.sendall(str(('identity',self.id,hashtag,malware_length,time.time(),self.malware)))
            data = ssl_sock.recv()
            datatuple = literal_eval(data)
            if datatuple[0]:
                print(' IoC Server Message: '+datatuple[1])
                ssl_sock.sendall(malware_instance)
                data = ssl_sock.recv()
                datatuple =literal_eval(data)
                if datatuple[0]:
                    print(' IoC Server Message: '+datatuple[1])
                else:
                    flag=False
                    print(' IoC Server Message: '+datatuple[1])
            else:
                flag=False
                print(' IoC Server Message: '+datatuple[1])
            print(data)

        except Exception,e:
            info =str(e)
            print(info)
            Logger().errorLogging(info)
        finally:
            return flag

    def local_server(self):
        try:
            server = SocketServer.TCPServer(local_server,RequestHandler)
            server.serve_forever()
        except Exception,e:
            info =str(e)
            print(info)
            Logger().errorLogging(info)

    def run(self):
        if self.send_malware():
            self.local_server()


class RequestHandler(SocketServer.BaseRequestHandler):

    def manipulate_data(self,data,filename):
        flag =True
        try:
            xmlfile = open(os.path.join(ANALYSIS_PATH,filename),'w')
            xmlfile.write(data)
            xmlfile.close()
        except Exception, e:
            flag =False
            print(str(e))
            Logger().errorLogging(str(e))
        return flag

    def deal_with_client(self,constream):
        try:
            data = constream.recv()
            datatuple= literal_eval(data) #datatuple form (maec_hash,client_id,malware_hash,malware_length,time_sending,filename)
            if (datatuple[2],datatuple[4]) in malware_info:
                constream.sendall(str(('ready','Ready to receive analysis results')))
                malware_length = datatuple[3]
                chunks=[]
                datarecv=0
                while datarecv < malware_length:
                    chunk = constream.recv(min(malware_length -datarecv, 2048))
                    if chunk == '':
                        raise RuntimeError("socket connection broken")
                    chunks.append(chunk)
                    datarecv = datarecv+ len(chunk)
                maec = ''.join(chunks)
                maec_check = hashlib.sha1(maec).hexdigest()
                if maec_check == datatuple[0]:
                    constream.send(str(('True','Results delivered successfully.')))
                    if self.manipulate_data(maec,datatuple[5]):
                        print('Results stored successfully')
                    else:
                        print('Results has not been stored.')
                else:
                    print('Results have not been delivered.')
                    constream.send(str(('False','Results failed  to be delivered.')))
        except Exception, e:
            print(str(e))
            Logger().errorLogging(str(e))

    def handle(self):
        server_certificate=None
        cacert = None
        server_key=None
        for cert in os.listdir(CERTIFICATES_PATH):
            if all(x in cert for x in ['pem', 'server']):
                server_certificate = os.path.join(CERTIFICATES_PATH,cert)
            if 'ca' in cert:
                cacert = os.path.join(CERTIFICATES_PATH,cert)
            if 'key' in cert:
                server_key =os.path.join(CERTIFICATES_PATH,cert)
        constream=ssl.wrap_socket(self.request,server_side=True,certfile=server_certificate,keyfile=server_key)
        try:
            self.deal_with_client(constream)
        finally:
            constream.shutdown(socket.SHUT_RDWR)
            constream.close()
        return


    def finish(self):
        return SocketServer.BaseRequestHandler.finish(self)

if __name__=='__main__':
    if len(sys.argv) ==2:
        IOCClient(sys.argv[1]).run()
    else:
        print('Please submit a malware file')
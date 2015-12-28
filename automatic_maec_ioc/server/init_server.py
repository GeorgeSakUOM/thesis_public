__author__ = 'george'
import socket,sys,ssl,fcntl,os,SocketServer
from ast import literal_eval
from common.configmanager import ConfigurationManager
from common.logger import Logger
SERVER_CERTIFICATE = ConfigurationManager.readServerConfig('server_certificate')
INIT_SERVER_ADDRESS = ConfigurationManager.readServerConfig('init_address')
INIT_SERVER_PORT = int(ConfigurationManager.readServerConfig('init_port'))
available_servers_address ={}
available_servers_environment_status = {}
available_servers=[]
server_address=(INIT_SERVER_ADDRESS,INIT_SERVER_PORT)

class TCPHandler(SocketServer.BaseRequestHandler):


    def manipulate_data(self,constream,data):
        global gui
        datatuple = literal_eval(data)
        if datatuple[0] =='identity':
            try:
                console.put(repr(constream.getpeername()))
                console.put("Server with %s was added"%data)
                self.available_servers_address_local[datatuple[1]]= eval(repr(constream.getpeername()))[0]
                constream.send(str((True,'Server identity stored')))
            except Exception,e:
                console.put(str(e))
                constream.send((False,'Server identity is not stored'))
        elif datatuple[0] =='status':
            if datatuple[2] in self.available_servers_address_local.keys():
                if datatuple[1]=='up':
                    try:
                        console.put("Analysis environment of server with identity %s is %s"%(datatuple[2],datatuple[1]))
                        self.available_servers_environment_status_local[datatuple[2]]=True
                        constream.send('IoC server is informed, and waiting')
                    except Exception, e:
                        console.put(str(e))
                        constream.send('IoC server has encountered a fatal error: %s '%str(e))
                elif datatuple[1]=='down':
                    try:
                        console.put("Analysis environment of server with identity %s is %s"%(datatuple[2],datatuple[1]))
                        del self.available_servers_address_local[datatuple[2]]
                        constream.send('IoC server is informed.')
                    except Exception, e:
                        console.put(str(e))
                        constream.send('IoC server has encountered a fatal error: %s '%str(e))
                elif datatuple[1]=='live':
                    try:
                        console.put("Server with identity %s is %s"%(datatuple[2],datatuple[1]))
                        self.available_servers_local.append(datatuple[2])
                        constream.send('IoC server is informed. And ready to send malware subjects')
                    except Exception, e:
                        console.put(str(e))
                        constream.send('IoC server has encountered a fatal error: %s '%str(e))
                elif datatuple[1]=='dead':
                    try:
                        console.put("Server with identity %s is %s"%(datatuple[2],datatuple[1]))
                        del self.available_servers_address_local[datatuple[2]]
                        del self.available_servers_environment_status_local[datatuple[2]]
                        constream.send('IoC server has been informed.')
                    except Exception, e:
                        console.put(str(e))
                        constream.send('IoC server has encountered a fatal error: %s '%str(e))
            else:
                console.put("Server with identity %s has not yet addressed identity"%datatuple[2])
                constream.send('Server has not yet addressed identity. Please run again the script.')
        return False

    def deal_with_client(self,constream):
        data = constream.recv()
        while data:
            if not self.manipulate_data(constream, data):
                break
            data = constream.recv()


    def handle(self):
        global available_servers,available_servers_environment_status,available_servers_address,console
        self.available_servers_local = available_servers
        self.available_servers_environment_status_local = available_servers_environment_status
        self.available_servers_address_local =available_servers_address
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
            console.put('Available servers addresses')
            console.put(str(self.available_servers_address_local))
            console.put('Available servers environment status')
            console.put(str(self.available_servers_environment_status_local))
            console.put('Available servers')
            console.put(str(self.available_servers_local))
        finally:
            constream.shutdown(socket.SHUT_RDWR)
            constream.close()
            available_servers =self.available_servers_local
            available_servers_environment_status = self.available_servers_environment_status_local
            available_servers_address =self.available_servers_address_local
        return

    def finish(self):
        global available_servers,available_servers_environment_status,available_servers_address,console
        console.put('Writing servers to analyzers file')
        analyzers = open('analyzers','a')
        fcntl.fcntl(analyzers,fcntl.LOCK_EX)
        analyzers.write(str(available_servers_address))
        fcntl.fcntl(analyzers,fcntl.LOCK_UN)
        analyzers.close()
        console.put('Servers that written in analyzers')
        console.put(str(available_servers_address))
        return SocketServer.BaseRequestHandler.finish(self)

class InitServer():

    def __init__(self,console_queue,analyzers):
        self.logger  = Logger()
        global available_servers_address,console
        available_servers_address= analyzers
        console = console_queue

    def run(self):
        global console
        try:
            console.put(str("Starting up on %s port %s"% server_address))
            server = SocketServer.ThreadingTCPServer(server_address,TCPHandler)
            server.serve_forever()
        except Exception,e:
            info=str(e)
            console.put(info)
            self.logger.errorLogging(info)

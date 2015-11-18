import socket
import sys 
import json
from ast import literal_eval
import ssl
CERTIFICATE = '/home/george/PycharmProjects/thesis_public/automatic_maec_ioc/server/server_certificate/iocserver.pem'
CERTIFICATECA = 'server_certificates/cacert.pem'
KEYFILE = '/home/george/PycharmProjects/thesis_public/automatic_maec_ioc/server/server_certificate/iocserver.key'

#global available_servers,available_servers_environment_status,available_servers_address
available_servers_address ={}
available_servers_environment_status = {}
available_servers=[]
#bindsock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server_adress=('localhost',8000)
#print >> sys.stderr, 'starting up on %s port %s '% server_adress
#
#bindsock.bind(server_adress)
#bindsock.listen(2)



#ssl_sock = ssl.wrap_socket(sock=sock,ca_certs=CERTIFICATECA,certfile=CERTIFICATE,cert_reqs=ssl.CERT_REQUIRED)
#ssl_sock.connect(server_adress)

import SocketServer



class TCPHandler(SocketServer.BaseRequestHandler):

    def manipulate_data(self,constream,data):
        datatuple = literal_eval(data)
        if datatuple[0] =='identity':
            try:
                print repr(constream.getpeername())
                print("Server with %s was added"%data)
                self.available_servers_address_local[datatuple[1]]= eval(repr(constream.getpeername()))[0]
                constream.send(str((True,'Server identity stored')))
            except Exception,e:
                print(str(e))
                constream.send((False,'Server identity is not stored'))
        elif datatuple[0] =='status':
            if datatuple[2] in self.available_servers_address_local.keys():
                if datatuple[1]=='up':
                    try:
                        print("Analysis environment of server with identity %s is %s"%(datatuple[2],datatuple[1]))
                        self.available_servers_environment_status_local[datatuple[2]]=True
                        constream.send('IoC server is informed, and waiting')
                    except Exception, e:
                        print(str(e))
                        constream.send('IoC server has encountered a fatal error: %s '%str(e))
                elif datatuple[1]=='down':
                    try:
                        print("Analysis environment of server with identity %s is %s"%(datatuple[2],datatuple[1]))
                        del self.available_servers_address_local[datatuple[2]]
                        constream.send('IoC server is informed.')
                    except Exception, e:
                        print(str(e))
                        constream.send('IoC server has encountered a fatal error: %s '%str(e))
                elif datatuple[1]=='live':
                    try:
                        print("Server with identity %s is %s"%(datatuple[2],datatuple[1]))
                        self.available_servers_local.append(datatuple[2])
                        constream.send('IoC server is informed. And ready to send malware subjects')
                    except Exception, e:
                        print(str(e))
                        constream.send('IoC server has encountered a fatal error: %s '%str(e))
                elif datatuple[1]=='dead':
                    try:
                        print("Server with identity %s is %s"%(datatuple[2],datatuple[1]))
                        del self.available_servers_address_local[datatuple[2]]
                        del self.available_servers_environment_status_local[datatuple[2]]
                        constream.send('IoC server has been informed.')
                    except Exception, e:
                        print(str(e))
                        constream.send('IoC server has encountered a fatal error: %s '%str(e))
            else:
                print("Server with identity %s has not yet addressed identity"%datatuple[2])
                constream.send('Server has not yet addressed identity. Please run again the script ')

            return False

    def deal_with_client(self,constream):
        data = constream.recv()
        while data:
            if not self.manipulate_data(constream, data):
                break
            data = constream.recv()


    def handle(self):
        global available_servers,available_servers_environment_status,available_servers_address
        self.available_servers_local = available_servers
        self.available_servers_environment_status_local = available_servers_environment_status
        self.available_servers_address_local =available_servers_address
        constream=ssl.wrap_socket(self.request,server_side=True,certfile=CERTIFICATE,keyfile=KEYFILE)
        try:
            self.deal_with_client(constream)
            print('Available servers adressses')
            print(self.available_servers_address_local)
            print('Available servers environment status')
            print(self.available_servers_environment_status_local)
            print('Available servers')
            print(self.available_servers_local)
        finally:
            constream.shutdown(socket.SHUT_RDWR)
            constream.close()

            available_servers =self.available_servers_local
            available_servers_environment_status = self.available_servers_environment_status_local
            available_servers_address =self.available_servers_address_local
    '''
    def finish(self):
        self.request.shutdown(socket.SHUT_RDWR)
        self.request.close()
    '''
if __name__=='__main__':
    print >> sys.stderr, 'starting up on %s port %s '% server_adress

    server = SocketServer.ThreadingTCPServer(server_adress,TCPHandler)
    server.serve_forever()

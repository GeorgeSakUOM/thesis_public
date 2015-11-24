__author__ = 'george'
import SocketServer,socket,ssl,sys,hashlib
from ast import literal_eval

cacert = '/home/george/PycharmProjects/thesis_public/automatic_maec_ioc/server/ssl/CA/cacert.pem'
key= '/home/george/PycharmProjects/thesis_public/automatic_maec_ioc/server/server_certificate/iocserver.key'
cert = '/home/george/PycharmProjects/thesis_public/automatic_maec_ioc/server/server_certificate/iocserver.pem'

server_address=('localhost',10000)
malware_received={}

class TCPHandler(SocketServer.BaseRequestHandler):

    def manipulate_data(self,constream,data):
        datatuple = literal_eval(data)
        print(datatuple)
        if datatuple[0] =='identity':
            malware_length =datatuple[3]
            try:
                print repr(constream.getpeername())
                print("Subject from client with identity %s was added"%datatuple[1])
                self.malware_received_local[datatuple[4]]= (datatuple[2],datatuple[1],literal_eval(repr(constream.getpeername()))[0])
                print(self.malware_received_local)
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
                else:
                    constream.sendall(str((False,'Try again')))
                #Here send it to analyzer
            except Exception,e:
                print(str(e))
                constream.send((False,'IoC Server fatal error. Try again later'))
        else:
            print("Client with identity %s has not yet addressed subject details"%datatuple[2])
            constream.send(str((False,'Client has not yet addressed subject details. Please run again the script ')))

        return False

    def deal_with_client(self,constream):
        data = constream.recv()
        while data:
            if not self.manipulate_data(constream, data):
                break
            data = constream.recv()


    def handle(self):
        global malware_received
        self.malware_received_local= malware_received
        constream=ssl.wrap_socket(self.request,server_side=True,certfile=cert,keyfile=key)
        try:
            self.deal_with_client(constream)
        finally:
            constream.shutdown(socket.SHUT_RDWR)
            constream.close()

        return

    def finish(self):
        return SocketServer.BaseRequestHandler.finish(self)

if __name__=='__main__':
    print >> sys.stderr, 'starting up on %s port %s '% server_address

    server = SocketServer.TCPServer(server_address,TCPHandler)
    server.serve_forever()
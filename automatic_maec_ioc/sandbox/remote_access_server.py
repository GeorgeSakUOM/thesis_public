__author__ = 'george'
import os,ssl,socket,subprocess,time,pprint,errno,commands,SocketServer,hashlib
from ast import literal_eval
from common.configmanager import ConfigurationManager
from common.logger import Logger
from ssl import SSLError
CUCKOO_PATH = ConfigurationManager.readServerConfig('cuckoo_path')
INETSIM_PATH = ConfigurationManager.readServerConfig('inetsim_path')
MALWARE_SAMPLES_PATH = ConfigurationManager.readServerConfig('malware_samples_path')
CERTIFICATES_PATH = ConfigurationManager.readServerConfig('certificates_path')
SERVER_ID = ConfigurationManager.readServerConfig('server_id')
INIT_SERVER_ADDRESS = ConfigurationManager.readServerConfig('init_server_address')
INIT_SERVER_PORT = int(ConfigurationManager.readServerConfig('init_server_port'))
SERVER_ADDRESS= ConfigurationManager.readServerConfig('address')
SERVER_PORT = int(ConfigurationManager.readServerConfig('port_number'))
init_server_address=(INIT_SERVER_ADDRESS,int(INIT_SERVER_PORT))
server_address = (SERVER_ADDRESS,SERVER_PORT)

class RequestHandler(SocketServer.BaseRequestHandler):

    def set_analysis_task(self,task):
        path = os.path.join(CUCKOO_PATH,'utils','submit.py')
        taskpath = os.path.join(MALWARE_SAMPLES_PATH,task)
        command = "python %s %s"%(path,taskpath)
        com_shell  ="\"%s; exec $SHELL\""%command
        gnome_command="gnome-terminal -x bash -c %s"%com_shell
        subprocess.call(gnome_command,shell=True)
        time.sleep(20)

    def deal_with_request(self,constream):
        print("Deal with request")
        #Receiving analysis request
        data = constream.recv()
        datatuple=literal_eval(data)
        task_id=datatuple[0]
        filename=datatuple[1]
        ref = datatuple[2]
        checksum=datatuple[3]
        length = datatuple[4]
        print("Receiving analysis task,filename:%s number:%d with %s: %s "%(filename,task_id,ref,checksum))
        constream.send('ready')
        chunks=[]
        datarecv=0
        while datarecv < length:
            chunk = constream.recv(min(length -datarecv, 2048))
            if chunk == b'':
                raise RuntimeError("socket connection broken")
            chunks.append(chunk)
            datarecv = datarecv+ len(chunk)
        malware = b''.join(chunks)
        mal_check = hashlib.sha1(malware).hexdigest()
        print("The checksum of the received subject is: %s"%mal_check)
        if mal_check == checksum:
            constream.send('Subject is delivered correctly.')
            malware_file = open(os.path.join(MALWARE_SAMPLES_PATH,filename),'wb')
            malware_file.write(malware)
            malware_file.close()
            try:
                self.set_analysis_task(filename)
                print('Analysis subject has been submitted succesfully.')
            except :
                constream.send('Failing to submit the subject  ')
        else:
            constream.send('Subject is not delivered correctly.')

    def handle(self):
        cacert=None
        server_certificate=None
        server_key = None
        for cert in os.listdir(CERTIFICATES_PATH):
            if all(x in cert for x in ['pem', 'server']):
                server_certificate = os.path.join(CERTIFICATES_PATH,cert)
            if 'ca' in cert:
                cacert = os.path.join(CERTIFICATES_PATH,cert)
            if 'key' in cert:
                server_key =os.path.join(CERTIFICATES_PATH,cert)
        constream=ssl.wrap_socket(self.request,server_side=True,certfile=server_certificate,keyfile=server_key,ca_certs=cacert)
        try:
            self.deal_with_request(constream)
            print('Request has committed successfully.')
        finally:
            constream.shutdown(socket.SHUT_RDWR)
            constream.close()
        return

    def finish(self):
        return SocketServer.BaseRequestHandler.finish(self)

class CuckooRemoteServer():

    def __init__(self,server_ip=None,server_port=None,ioc_server_ip=None,ioc_server_port=None,):
        self.logger = Logger()
        self.id = SERVER_ID
        if server_ip is not None and server_port is not None:
            self.server_address = (server_ip,server_port)
        else:
            self.server_address=server_address

        if ioc_server_ip is not None and ioc_server_port is not None:
            self.ioc_server_address = (ioc_server_ip,ioc_server_port)
        else:
            self.ioc_server_address=init_server_address

    def get_server_id(self):
        return self.id

    def communicate_identity(self):
        try:
            cacert=None
            server_certificate=None
            server_key = None
            for cert in os.listdir(CERTIFICATES_PATH):
                if all(x in cert for x in ['pem', 'server']):
                    server_certificate = os.path.join(CERTIFICATES_PATH,cert)
                if 'ca' in cert:
                    cacert = os.path.join(CERTIFICATES_PATH,cert)
                if 'key' in cert:
                    server_key =os.path.join(CERTIFICATES_PATH,cert)
            sock= socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            ssl_sock = ssl.wrap_socket(sock=sock,ca_certs=cacert,certfile=server_certificate,keyfile=server_key,cert_reqs=ssl.CERT_REQUIRED)
            ssl_sock.connect(self.ioc_server_address)
            print repr(ssl_sock.getpeername())
            print ssl_sock.cipher()
            print pprint.pformat(ssl_sock.getpeercert())
            print("Sending identity")
            ssl_sock.send(str(('identity',self.get_server_id())))
            data = ssl_sock.recv()
            datatuple = literal_eval(data)
            if datatuple[0]==True:
                flag=True
            else:
                flag=False
            print("IoC Server message: %s"%datatuple[1])
            ssl_sock.close()
            time.sleep(10)
        except SSLError,ssler:
            errorNum = ssler.errno
            errorCode = errno.errorcode[errorNum]
            errorString= os.strerror(errorNum)
            errorFile = ssler.filename
            info=(errorNum,errorCode,errorString,errorFile)
            self.logger.errorLogging(msg=info)
            flag=False
            print('SSL Error: '+str(info))
        except socket.error, socker :
            errorNum = socker.errno
            errorCode = errno.errorcode[errorNum]
            errorString= os.strerror(errorNum)
            errorFile = socker.filename
            info=(errorNum,errorCode,errorString,errorFile)
            self.logger.errorLogging(msg=info)
            flag=False
            print('Socket Error: '+str(info))
        except Exception, e :
            info = (str(e))
            flag =False
            print('Error',info)
            self.logger.errorLogging(msg=info)
        return flag

    def communicate_initialization_status(self,status='up'):
        flag = True
        try:
            cacert=None
            server_certificate=None
            server_key = None
            for cert in os.listdir(CERTIFICATES_PATH):
                if all(x in cert for x in ['pem', 'server']):
                    server_certificate = os.path.join(CERTIFICATES_PATH,cert)
                if 'ca' in cert:
                    cacert = os.path.join(CERTIFICATES_PATH,cert)
                if 'key' in cert:
                    server_key =os.path.join(CERTIFICATES_PATH,cert)
            sock= socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            ssl_sock = ssl.wrap_socket(sock=sock,ca_certs=cacert,certfile=server_certificate,keyfile=server_key,cert_reqs=ssl.CERT_REQUIRED)
            ssl_sock.connect(self.ioc_server_address)
            print("Sending analysis environment initialization status to IoC Server")
            ssl_sock.send(str(('status',status,self.get_server_id())))
            data = ssl_sock.recv()
            print(data)
            ssl_sock.close()
            time.sleep(10)
        except SSLError,ssler:
            errorNum = ssler.errno
            errorCode = errno.errorcode[errorNum]
            errorString= os.strerror(errorNum)
            errorFile = ssler.filename
            info=(errorNum,errorCode,errorString,errorFile)
            self.logger.errorLogging(msg=info)
            flag=False
            print('SSL Error: '+str(info))
        except socket.error, socker :
            errorNum = socker.errno
            errorCode = errno.errorcode[errorNum]
            errorString= os.strerror(errorNum)
            errorFile = socker.filename
            info=(errorNum,errorCode,errorString,errorFile)
            self.logger.errorLogging(msg=info)
            flag=False
            print('Socket Error: '+str(info))
        except Exception, e :
            info = (str(e))
            flag =False
            print('Error',info)
            self.logger.errorLogging(msg=info)
        return flag

    def initialize_analysis_environment(self):
        flag1=False
        flag2=False
        flag3=False
        try:
            print('Initializing Analysis environment ....')
            print('Starting InetSim......')
            if not 'inetsim' in commands.getoutput('ps -A'):
                print('Inetsim needs to be root to run,please provide sudo  password: ')
                password = raw_input('Password:')
                command="cd %s ;echo \'%s\' |sudo -S ./inetsim "%(INETSIM_PATH,password)
                com_shell ="\"%s; exec $SHELL\""%command
                gnome_command="gnome-terminal -x bash -c %s"%com_shell
                subprocess.call(gnome_command,shell=True)
                time.sleep(10)
                if 'inetsim' in commands.getoutput('ps -A'):
                    print('InetSim is up and running')
                    flag1=True
                else:
                    print('InetSim is not activated. Analysis result does not contain network analysis')
            else:
                print('InetSim is up and running')
                flag1=True

            print("Starting virtual machine....")
            if not 'VirtualBox' in commands.getoutput('ps -A'):
                vboxcommand='VBoxManage startvm cuckoo1'
                com_shell  ="\"%s; exec $SHELL\""%vboxcommand
                gnome_command="gnome-terminal -x bash -c %s"%com_shell
                subprocess.call(gnome_command,shell=True)
                time.sleep(20)
                if 'VirtualBox' in commands.getoutput('ps -A'):
                    print('Virtual machine is up and running')
                    flag2=True
                else:
                    print('Virtual machine is not activated. Analysis result does not contain network analysis')
            else:
                print('Virtual machine is up and running')
                flag2=True

            print('Starting Cuckoo')
            if 'cuckoo' in commands.getoutput('ps -at'):
                print('Cuckoo Sandbox is up and running 1')
                flag3=True
            else:
                cuckoocommand = "python %scuckoo.py"%CUCKOO_PATH
                com_shell ="\"%s; exec $SHELL\""%cuckoocommand
                gnome_command="gnome-terminal -x bash -c %s"%com_shell
                subprocess.call(gnome_command,shell=True)
                time.sleep(10)
                if 'cuckoo' in commands.getoutput('ps -at'):
                    print('Cuckoo Sandbox is up and running')
                    flag3=True
                    time.sleep(10)
                else:
                    print('Cuckoo sandbox is not activated.')

        except Exception,e:
            print(str(e))
            self.logger.errorLogging(msg=str(e))
        finally:
            return (flag1,flag2,flag3)



    def run_server(self):
        try:
            cacert=None
            server_certificate=None
            server_key = None
            for cert in os.listdir(CERTIFICATES_PATH):
                if all(x in cert for x in ['pem', 'server']):
                    server_certificate = os.path.join(CERTIFICATES_PATH,cert)
                if 'ca' in cert:
                    cacert = os.path.join(CERTIFICATES_PATH,cert)
                if 'key' in cert:
                    server_key =os.path.join(CERTIFICATES_PATH,cert)
            sock= socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            ssl_sock = ssl.wrap_socket(sock=sock,ca_certs=cacert,certfile=server_certificate,keyfile=server_key,cert_reqs=ssl.CERT_REQUIRED)
            try:
                print('Starting up on %s port %s '% self.server_address)
                server = SocketServer.TCPServer(self.server_address,RequestHandler)
                ssl_sock.connect(self.ioc_server_address)
                print("Sending Cuckoo server status to IoC Server")
                ssl_sock.send(str(('status','live',self.get_server_id())))
                data = ssl_sock.recv()
                print(data)
                ssl_sock.shutdown(socket.SHUT_RDWR)
                ssl_sock.close()
                print('Waiting for a connection.....')
                server.serve_forever()
            except socket.error,socker:
                errorNum = socker.errno
                errorCode = errno.errorcode[errorNum]
                errorString= os.strerror(errorNum)
                errorFile = socker.filename
                info=(errorNum,errorCode,errorString,errorFile)
                self.logger.errorLogging(msg=info)
                print('Socket Error: '+str(info))
                ssl_sock.connect(self.ioc_server_address)
                print("Sending Cuckoo server status to IoC Server")
                ssl_sock.send(str(('status','dead',self.get_server_id())))
                data = ssl_sock.recv()
                print(data)
                ssl_sock.close()
        except SSLError,ssler:
            errorNum = ssler.errno
            errorCode = errno.errorcode[errorNum]
            errorString= os.strerror(errorNum)
            errorFile = ssler.filename
            info=(errorNum,errorCode,errorString,errorFile)
            self.logger.errorLogging(msg=info)
            print('SSL Error: '+str(info))
        except socket.error, socker :
            errorNum = socker.errno
            errorCode = errno.errorcode[errorNum]
            errorString= os.strerror(errorNum)
            errorFile = socker.filename
            info=(errorNum,errorCode,errorString,errorFile)
            self.logger.errorLogging(msg=info)
            print('Socket Error: '+str(info))
        except Exception, e :
            info = (str(e))
            print('Error',info)
            self.logger.errorLogging(msg=info)

    def server_protocol(self):
        #Communicate  server identity to iocserever.
        flag = self.communicate_identity()
        #Start server and wait for samples
        if flag:
            analysis_environment_report = (True,True,True)#self.initialize_analysis_environment()
            if analysis_environment_report[2] == False:
                self.communicate_initialization_status('down')
                print("Cuckoo seems to be down")
                print("Server terminates. Check log files")
            else:
                self.communicate_initialization_status('up')
                self.run_server()
        else:
            print('Failed to communicate server identity. Check error.log')

    def run(self):
        try:
            self.server_protocol()
        except Exception,e:
            print(str(e))
            self.logger.errorLogging(msg=str(e))

if __name__ =='__main__':
    CuckooRemoteServer().run()


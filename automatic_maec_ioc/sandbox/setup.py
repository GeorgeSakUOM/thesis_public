__author__ = 'george'
import os,sys, ConfigParser,argparse,subprocess,uuid

DEFAULT_CUCKOO_PATH= '/opt/cuckoo/'
DEFAULT_INETSIM_PATH = '/opt/inetsim/'
DEFAULT_SERVER_HOST = 'localhost'
DEFAULT_SERVER_PORT = 5000
DEFAULT_INIT_SERVER_ADDRESS = 'localhost'
DEFAULT_INIT_SERVER_PORT = 8000

def main():
    parser = argparse.ArgumentParser(description='This program configure cuckoo remote access server')
    parser.add_argument('-cuckoopath',action='store',dest='cuckoopath', help='path of cuckoo directory')
    parser.add_argument('-inetsimpath',action='store',dest='inetsimpath', help='path of inetsim directory')
    parser.add_argument('-host',action='store',dest='host',help='host of Cuckoo remote access server')
    parser.add_argument('-port',action='store',dest='port',help='Cuckoo remote access server port')
    parser.add_argument('-initservaddr',action='store',dest='initserveraddr',help='IOC server address')
    parser.add_argument('-initservport',action='store',dest='initserverport',help='IOC server port')

    args = parser.parse_args()
    if args.cuckoopath is not None:
        CUCKOO_PATH = args.cuckoopath
    else:
        CUCKOO_PATH = DEFAULT_CUCKOO_PATH
    print "Cuckoo path is initialized to : %s"%CUCKOO_PATH

    if args.inetsimpath is not None:
        INETSIM_PATH = args.inetsimpath
    else:
        INETSIM_PATH = DEFAULT_INETSIM_PATH
    print "InetSim path is initialized to : %s"%INETSIM_PATH

    if args.host is not None:
        SERVER_HOST = args.host
    else:
        SERVER_HOST = DEFAULT_SERVER_HOST
    print "Server host is initialized to : %s"%SERVER_HOST

    if args.port is not None:
        SERVER_PORT = args.port
    else:
        SERVER_PORT = DEFAULT_SERVER_PORT
    print "Server host is initialized to : %s"%SERVER_PORT


    if args.initserveraddr is not None:
        INIT_SERVER_ADDRESS = args.initserveraddr
    else:
        INIT_SERVER_ADDRESS = DEFAULT_INIT_SERVER_ADDRESS
    print "IOC Server port is initialized to : %s"%INIT_SERVER_ADDRESS

    if args.initserverport is not None:
        INIT_SERVER_PORT = args.initserverport
    else:
        INIT_SERVER_PORT = DEFAULT_INIT_SERVER_PORT
    print "IOC Server port is initialized to : %s"%INIT_SERVER_PORT

    try:
        print('Creating configuration directory.')
        subprocess.call(['mkdir','conf'])
        print('Creating log directory.')
        subprocess.call(['mkdir','log'])
        print('Creating certificates directory')
        subprocess.call(['mkdir','server_certificates'])
        print('Creating malware samples hub')
        subprocess.call(['mkdir','malware_pool'])
        print('Copying cuckoo plugin to cuckoo reporting modules ')
        plugin_path = os.path.join(CUCKOO_PATH,'modules/reporting/')
        subprocess.call(["cp","extensions/cuckoo_messenger.py",plugin_path])
        print('Write Cuckoo reporting.conf file')

        cuckooconfig = ConfigParser.RawConfigParser()
        cuckooconfig.add_section('cuckoo_messenger')
        cuckooconfig.set('cuckoo_messenger','enabled','yes')
        with open(os.path.abspath(os.path.join(CUCKOO_PATH,'conf','reporting.conf')), 'a') as configfile:
            cuckooconfig.write(configfile)
            configfile.close()

    except Exception, e:
        print e

    try:
        config = ConfigParser.RawConfigParser(allow_no_value=True)
        # Initialize configuration file of logs
        print('Initialize configuration file of logs')
        config.add_section('Logging')
        config.set('Logging', 'LOG_PATH', os.path.abspath(os.path.join(os.path.dirname(__file__),"log")))
        config.set('Logging', 'ERROR_FILENAME', 'error.log')
        config.set('Logging', 'WARNING_FILENAME', 'warning.log')
        config.set('Logging', 'DEBUG_FILENAME', 'debug.log')
        config.set('Logging', 'CRITICAL_FILENAME', 'critical_error.log')
        config.set('Logging', 'INFO_FILENAME', 'info.log')
        config.set('Logging', 'FORMAT', '%(levelname)s:%(name)s:%(asctime)s:%(message)s')
        config.set('Logging', 'DATEFORMAT', '%d-%m-%Y %I:%M:%S %p')
        # Writing configuration file to 'log.conf'
        print("Writing configuration file to 'log.conf'")
        with open(os.path.abspath(os.path.join(os.path.dirname(__file__),'conf','log.conf')), 'w') as configfile:
            config.write(configfile)
            configfile.close()
        config.remove_section('Logging')
        #Initialize configuration file of Server
        print('Initialize configuration file of Server')
        config.add_section('Server')
        config.set('Server', 'CUCKOO_PATH', CUCKOO_PATH)
        config.set('Server', 'INETSIM_PATH', INETSIM_PATH)
        config.set('Server', 'ADDRESS', SERVER_HOST)
        config.set('Server', 'PORT_NUMBER', SERVER_PORT)
        config.set('Server','SERVER_ID',uuid.uuid1())
        config.set('Server','INIT_SERVER_ADDRESS',INIT_SERVER_ADDRESS)
        config.set('Server','INIT_SERVER_PORT',INIT_SERVER_PORT)
        config.set('Server', 'MALWARE_SAMPLES_PATH', os.path.abspath(os.path.join(os.path.dirname(__file__),"malware_pool")))
        config.set('Server', 'CERTIFICATES_PATH', os.path.abspath(os.path.join(os.path.dirname(__file__),"server_certificates")))
        # Writing configuration file to 'server.conf'
        print("Writing configuration file to 'server.conf'")
        with open(os.path.abspath(os.path.join(os.path.dirname(__file__),'conf','server.conf')), 'w') as configfile:
            config.write(configfile)
            configfile.close()
        config.remove_section('Server')
        print('Configuration Completed successfully')
    except Exception, e :
         print e
if __name__ == '__main__':
    main()


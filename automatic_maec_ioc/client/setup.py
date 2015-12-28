__author__ = 'george'

import argparse,ConfigParser,os,subprocess,uuid

DEFAULT_ANALYSIS_DIRECTORY_PATH=os.path.abspath(os.path.join(os.path.dirname(__file__),"analysis_results"))
DEFAULT_MALWARE_SUBJECTS_DIRECTORY_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__),"malware_pool"))
DEFAULT_SERVER_CERTIFICATE_PATH=os.path.abspath(os.path.join(os.path.dirname(__file__),"certificate"))
DEFAULT_IOC_SERVER_ADDRESS ='localhost'
DEFAULT_IOC_SERVER_PORT =10500
DEFAULT_CLIENT_ADDRESS = 'localhost'
DEFAULT_CLIENT_PORT = 7000

def main():
    parser = argparse.ArgumentParser(description='This program configure ioc server')
    parser.add_argument('-apath',action='store',dest='apath', help='Path of analysis directory. Here are stored results coming from ioc server')
    parser.add_argument('-mpath',action='store',dest='mpath', help='Path of malware samples directory. Here are stored malware subjects  for analysis')
    parser.add_argument('-host',action='store',dest='host',help='Host address of IoC server')
    parser.add_argument('-port',action='store',dest='port',help='IoC server port')
    parser.add_argument('-chost',action='store',dest='chost',help='Host address of Client server')
    parser.add_argument('-cport',action='store',dest='cport',help='Client server port')
    args = parser.parse_args()

    if args.apath is not None:
        ANALYSIS_PATH = args.apath
    else:
        ANALYSIS_PATH = DEFAULT_ANALYSIS_DIRECTORY_PATH

    if args.mpath is not None:
        MALWARE_PATH = args.mpath
    else:
        MALWARE_PATH = DEFAULT_MALWARE_SUBJECTS_DIRECTORY_PATH

    if args.host is not None:
        IOC_SERVER_HOST = args.host
    else:
        IOC_SERVER_HOST = DEFAULT_IOC_SERVER_ADDRESS

    if args.port is not None:
        IOC_SERVER_PORT = args.port
    else:
        IOC_SERVER_PORT = DEFAULT_IOC_SERVER_PORT

    if args.chost is not None:
        SERVER_HOST = args.chost
    else:
        SERVER_HOST = DEFAULT_CLIENT_ADDRESS

    if args.cport is not None:
        SERVER_PORT = args.cport
    else:
        SERVER_PORT = DEFAULT_CLIENT_PORT

    try:
        print('Creating certificates directory...')
        subprocess.call(['mkdir','certificate'])
        print('Creating logs directory...')
        subprocess.call(['mkdir','log'])
        print('Creating conf directory...')
        subprocess.call(['mkdir','conf'])
        if args.apath is None:
            print('Creating analysis results  directory...')
            subprocess.call(['mkdir','analsysis_results'])
        if args.mpath is None:
            print('Creating malware pool...')
            subprocess.call(['mkdir','malware_pool'])

    except Exception, e:
        print(str(e))

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
        print('Initialize configuration file of local Server')
        config.add_section('Server')
        config.set('Server', 'ANALYSIS_PATH',ANALYSIS_PATH)
        config.set('Server','MALWARE_PATH',MALWARE_PATH)
        config.set('Server', 'ADDRESS', SERVER_HOST)
        config.set('Server', 'PORT', SERVER_PORT)
        config.set('Server', 'IOC_ADDRESS', IOC_SERVER_HOST)
        config.set('Server', 'IOC_PORT', IOC_SERVER_PORT)
        config.set('Server', 'SERVER_CERTIFICATE', DEFAULT_SERVER_CERTIFICATE_PATH)
        config.set('Server','SERVER_ID',uuid.uuid1())
        # Writing configuration file to 'server.conf'
        print("Writing configuration file to 'server.conf'")
        with open(os.path.abspath(os.path.join(os.path.dirname(__file__),'conf','server.conf')), 'w') as configfile:
            config.write(configfile)
            configfile.close()
        config.remove_section('Server')
    except Exception,e:
        print(str(e))



if __name__=='__main__':
    main()
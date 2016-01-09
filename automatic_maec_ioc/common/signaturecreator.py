__author__ = 'george'

import argparse,subprocess,os
from configmanager import ConfigurationManager

SSL_PATH=ConfigurationManager.readServerConfig(variable='ssl')

def getlastcertindex():
    with open(os.path.join(SSL_PATH,'CA','index.txt'),'r') as caindex:
            line=''
            for line in caindex:
                pass
            last=line
    caindex.close()
    num = [int(val) for val in last.split() if val.isdigit()]
    return num[0]

def copycert(name,num):
    certs=os.listdir(os.path.join(SSL_PATH,'CA','newcerts'))
    certname=[cert for cert in certs if str(num) in cert][0]
    with open(os.path.join(SSL_PATH,'CA','newcerts',certname),'r') as certfile:
        data=certfile.read()
    certfile.close()
    with open(name+'.pem','w') as newcert:
        newcert.write(data)
    newcert.close()

def main():
    parser = argparse.ArgumentParser(description='This program generates signed ceritficate in mode 1 and client keys and certificates in mode 2 ')
    parser.add_argument('-mode',action='store',dest='mode', help='Action mode. 1 - For certificate generation. 2 - For key and certificate generation')
    parser.add_argument('-req',action='store',dest='req', help='Certificate Signature Request filepath')
    parser.add_argument('-kname',action='store',dest='kname',help='Name of the generated key file. Default client.key')
    parser.add_argument('-cpath',action='store',dest='cpath', help='Openssl configuration file path. Default:/etc/ssl/openssl.cnf')
    args = parser.parse_args()

    if args.kname:
        keyname=args.kname
    else:
        keyname='client'

    if args.cpath:
        sslconfpath=args.cpath
    else:
        sslconfpath ='/etc/ssl/openssl.cnf'

    #Commands list
    #-1- Key generation
    command1= 'openssl genrsa -out '+keyname+'.key 1024'
    command2='openssl req -new -key '+keyname+'.key -out '+keyname+'.csr'
    command3 = 'openssl ca -in '+keyname+'.csr -config '+sslconfpath
    if int(args.mode)==1:
        try:
            if args.req:
                certreq=args.req
                print('Creating client certificate...')
                command4 = 'openssl ca -in '+certreq+' -config '+sslconfpath
                certindexbefore=getlastcertindex()
                subprocess.call(command4,shell=True)
                newcertindex =getlastcertindex()
                if certindexbefore<newcertindex:
                    copycert(keyname,newcertindex)
                else:
                    print('Error in certificate generation. Continue using this script in mode 1 OR retry with the suggested transformations')
            else:
                print('Please provide a certificate request file')
        except Exception, e:
            print(str(e))
    elif int(args.mode)==2:
        try:
            print('Creating client key and certificate...')
            print('Generating key....')
            subprocess.call(command1,shell=True)
            print('Generating certificate request ....')
            subprocess.call(command2,shell=True)
            certindexbefore = getlastcertindex()
            print('Generating certificate ...')
            subprocess.call(command3,shell=True)
            newcertindex = getlastcertindex()
            if certindexbefore<newcertindex :
                copycert(keyname,newcertindex)
            else:
                print('Error in certificate generation. Continue using this script in mode 1 OR retry with the suggested transformations')
        except Exception, e:
            print(str(e))
    else:
        print('Please select functionality mode... ')

if __name__=='__main__':
    main()
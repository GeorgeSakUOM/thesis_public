import socket
import sys 

sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server_adress=('localhost',10000) 
print >> sys.stderr, 'starting up on %s port %s '% server_adress
sock.bind(server_adress)
sock.listen(1)

dbfilename='cuckko_results'
while True:
    print >>sys.stderr, 'waiting for a connection' 
    connection, client_address = sock.accept()
    try:
        print >>sys.stderr, 'connection from', client_address
        #connection.send('200')
        # Receive the data in small chunks and retransmit it
        dbfile =open(dbfilename,'a')
        while True:
            
            data = connection.recv(16)
            print >>sys.stderr, 'received "%s"' % data
            if data:
                dbfile.write(data)
                #print >>sys.stderr, 'sending data back to the client'
                connection.sendall(data)
            else:
                print >>sys.stderr, 'no more data from', client_address
                break
            
    finally:
        # Clean up the connection
        connection.close()
        dbfile.close()

 




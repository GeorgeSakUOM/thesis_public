import socket
import sys 
import json

sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server_adress=('localhost',10000) 
print >> sys.stderr, 'starting up on %s port %s '% server_adress
sock.bind(server_adress)
sock.listen(1)

dbfilename='cuckoo_results1'
chunks =[]
messaselength =0

while True:
    print('waiting for a connection') 
    connection, client_address = sock.accept()
    try:
        print >>sys.stderr, 'connection from', client_address
        # Receive the data in small chunks and retransmit it
        while True:
            data = connection.recv(1024)
            #print('received "%s"\n' % data)
            messaselength+=len(data)
            if data:
                #print >>sys.stderr, 'sending data back to the client'
                connection.sendall(data)
            else:
                print >>sys.stderr, 'no more data from', client_address
                break
            chunks.append(data)
    finally:
        # Clean up the connection
        connection.close()
        dbfile =open(dbfilename,'w')
        result = json.loads(''.join(chunks))
        #print(repr(result))
        print('Data received :',messaselength)
        json.dump(result, dbfile)
        dbfile.close()

 




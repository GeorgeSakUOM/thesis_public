'''


@author: george
'''

maecVocabs={'ActionObjectAssociationTypeVocab-1.0':['input','output','side-effect'],'DebuggingActionNameVocab-1.0':['check for remote debugger','check for kernel debugger'],
            'DeviceDriverActionNameVocab-1.1':['load and call driver','load driver','unload driver','emulate driver'],'DirectoryActionNameVocab-1.1':['create directory',
            'delete directory','monitor directory','hide directory'],'DiskActionNameVocab-1.1':['get disk type','get disk attributes','mount disk','unmount disk','emulate disk'
            ,'list disks','monitor disks'],'DNSActionNameVocab-1.0':['send dns query','send reverse dns lookup'],'FileActionNameVocab-1.1':['create file','delete file',
            'copy file','create file symbolic link','find file','get file attributes','set file attributes','lock file','unlock file','modify file','move file','open file',
            'read from file','write to file','rename file','create file alternate data stream','send control code to file','create file mapping','open file mapping',
            'execute file','hide file','close file'],'FTPAActionNameVocab-1.0':['connect to ftp server','disconnect from ftp server','send ftp command'],'GUIActionNameVocab-1.0':
            ['create window','kill window','create dialog box','enumerate windows','find window','hide window','show window'],'HookingActionNameVocab-1.1':['add system call hook',
            'add windows hook','hide hook'],'HTTPActionNameVocab-1.0':['send http get request','send http head request','send http post request','send http put request',
            'send http delete request','send http trace request','send http options request','send http connect request','send http patch request','receive http response'],
            'IPCActionNameVocab-1.0':['create named pipe','delete named pipe','connect to named pipe','disconnect from named pipe','read from named pipe','write to named pipe',
            'create mailslot','read from mailslot','write to mailslot'],'IRCActionNameVocab-1.0':['connect to irc server','disconnect from irc server','set irc nickname',
            'join irc channel','leave irc channel','send irc private message','receive irc private message'],'LibraryActionNameVocab-1.1':['enumerate libraries','free library',
            'load library','get function address','call library function'],'NetworkActionNameVocab-1.1':['open port','close port','connect to ip','disconnect from ip',
            'connect to url','connect to socket address','download file','upload file','listen on port','send email message','send icmp request','send network packet',
            'receive network packet'],'NetworkShareActionNameVocab-1.0':['add connection to network share','add network share','delete network share','connect to network share',
            'disconnect from network share','enumerate network shares'],'ProcessActionNameVocab-1.0':['create process','kill process','create process as user','enumerate processes',
            'open process','flush process instruction cache','get process current directory','set process current directory','get process environment variable','set process environment variable',
            'sleep process','get process startup info'],'ProcessMemoryActionNameVocab-1.0':['allocate process virtual memory','free process virtual memory','modify process virtual memory protection',
            'read from process memory','write to process memory','map file into process','unmap file from process','map library into process'],'ProcessThreadActionNameVocab-1.0':
            ['create thread','kill thread','create remote thread in process','enumerate threads','get thread username','impersonate process','revert thread to self','get thread context',
            'set thread context','queue apc in thread'],'RegistryActionNameVocab-1.0':['create registry key','delete registry key','open registry key','close registry key',
            'create registry key value','delete registry key value','enumerate registry key subkeys','enumerate registry key values','get registry key attributes','read registry key value',
            'modify registry key value','modify registry key','monitor registry key'],'ServiceActionNameVocab-1.1':['create service','delete service','start service','stop service',
            'enumerate services','modify service configurations','open service','send control code to service'],'SocketActionNameVocab-1.0':['accept socket connection',
            'bind address to socket','create socket','close socket','connect to socket','disconnect from socket','listen on socket','send data on socket','receive data on socket',
            'send data to address on socket','get host by address','get host by name'],'SynchronizationActionNameVocab-1.0':['create mutex','delete mutex','open mutex','release mutex',
            'create semaphore','delete semaphore','open semaphore','release semaphore','create event','delete event','open event','reset event','create critical section', 
            'delete critical section','open critical section','release critical  section'],'SystemActionNameVocab-1.0':['add scheduled task','shutdown system','sleep system',
            'get elapsed system up time','get netbios name','set netbios name','get system host name','set system host name','get system time','set system time','get system local time',
            'set system local time','get username','enumerate system handles','get system global flags','set system global flags','get windows directory','get windows system directory',
            'get windows temporary files directory'],'UserActionNameVocab-1.1':['add user','delete user','enumerate users','get user attributes','logon as user','change password',
            'add user to group','remove user from group','invoke user privilege'],'ImportanceTypeVocab-1.0':['high','medium','low','informational','numeric','unknown'],'MalwareEntityTypeVocab-1.0':[
            'instance','family','class'],'CapabilityObjectiveRelationshipTypeVocab-1.0':['child of','parent of','incorporates','icorporatedby'],'CommonCapabilityPropertiesVocab-1.0':[
            'encryption algorithm','protocol used'],'MalwareCapabilityVocab-1.0':['command and control','remote machine manipulation','privilege escalation','data theft','spying',
            'secondary operation','anti-detection','anti-code analysis','infection/propagation','anti-behavioral analysis','integrity violation','data exfiltration','probing',
            'anti-removal','security degradation','availability violation','destruction','fraud','persistence','machine access/control']}
maecBundle={'maecVocabs':maecVocabs} 


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
            'anti-removal','security degradation','availability violation','destruction','fraud','persistence','machine access/control'],'MalwareLabelVocab-1.0':['adware',
            'appender','backdoor','boot sector virus','bot','clicker','companion virus','cavity filler','data diddler','downloader','dropper file','file infector virus','fork bomb',
            'greyware','implant','infector','keylogger','kleptographic worm','macro virus','malcode','mass-mailer','metamorphic virus','mid-infector','mobile code','multipartite virus',
            'password stealer','polymorphic virus','premium dialer/smser','prepender','ransomware','rat','rogue anti-malware','rootkit','shellcode','spaghetti packer','spyware',
            'trojan horse','variant','virus','wabbit','web bug','wiper','worm','zip bomb'],'AntiBehavioralAnalysisPropertiesVocab-1.0':['targeted vm','targeted sandbox'],
            'AntiBehavioralAnalysisStrategicObjectivesVocab-1.0':['anti-vm','anti-sandbox'],'AntiBehavioralAnalysisTacticalObjectivesVocab-1.0':['detect vm environment',
            'overload sandbox','prevent execution in sandbox','detect sandbox environment','prevent execution in vm'],'AntiCodeAnalysisStrategicObjjectiveVocab-1.0':['anti-debugging',
            'code obfuscation','anti-disassembly'],'AntiCodeAnalysisTacticalObjectiveVocab-1.0':['transform control flow','restructure arrays','detect debugging','prevent debugging',
            'defeat flow-oriented (recursive traversal) disassemblers','defeat linear disassemblers','obfuscate instructions','obfuscate imports','defeat call graph generation',
            'obfuscate runtime code'],'AntiDetectionStrategicObjectivesVocab-1.0':['security software evasion','hide executing code','self-modification','anti-memory forensics',
            'hide non-executing code','hide malware artifacts'],'AntiDetectionTacticalObjectivesVocab-1.0':['hide open network ports','execute before/external to','kernel hypervisor',
            'encrypt self','hide processes','hide network traffic','change/add content','execute stealthy code','hide registry artifacts','hide userspace libraries','hide arbitrary virtual memory',
            'execute non-main cpu code','feed misinformation during physical memory acquisition','prevent physical memory acquisition','prevent native api hooking','obfuscate artifact properties',
            'hide kernel modules','hide code in file','hide services','hide file system artifacts','hide threads'],'AntiRemovalStrategicObjectivesVocab-1.0':['prevent malware artifact access',
            'prevent malware artifact deletion'],'AntiRemovalTacticalObjevtivesVocab-1.0':['prevent registry deletion','prevent api unhooking','prevent file access','prevent memory access',
            'prevent registry  access','prevent file deletion'],'AvailabilityViolationPropertiesVocab-1.0':['cryptocurrency type'],'AvailabilityViolationStrategicObjectivesVocab-1.0':
            ['compromise data availability','compromise system availability','cosume system resources'],'AvailabilityViolationTacticalObjectivesVocab-1.0':['denial of service',
            'compromise local system availability','crack passwords','mine of cryptocurrency','compromise access to information assets'],'CommandandControlPropertiesVocab-1.0':
            ['frequency'],'CommandandControlStrategicObjectivesVocab-1.0':['determine c2 server','receive data from c2 server','send data to c2 server'],'CommandandControlTacticalObjectivesVocab-1.0':
            ['check for payload','validate data','control malware via remote command','send system information','send heartbeat data','generate c2 domain name(s)','update configuration'],
            'DataExfiltrationPropertiesVocab-1.0':['archive type','file type'],'DataExfiltrationStrategicObjectivesVocab-1.0':['perform data exfiltration','obfuscate data for exfiltration',
            'stage data for exfiltration'],'DataExfiltrationTacticalObjectivesVocab-1.0':['exfiltrate via covert channel','exfiltrate via fax','exfiltrate via physical media',
            'encrypt data','exfiltrate via network','hide data','package data','exfiltrate via  dumpster dive','move data to staging server','exfiltrate via voip/phone'],'DataTheftPropertiesVocab-1.0':
            ['targeted application','targeted website'],'DataTheftStrategicObjectivesVocab-1.0':['steal stored information','steal user data','steal system information',
            'steal authentication credentials'],'DataTheftTacticalObjectivesVocab-1.0':['steal dialed phone numbers','steal email data','steal referrer urls','steal cryptocurrency data',
            'steal pki software certificate','steal browser cache','steal serial numbers','steal sms database','steal cookie','steal password hash','steal make/model','steal documents',
            'steal network address','steal open port','steal images','steal browser history','steal web/network credential','steal pki key','steal contact list data','steal database content'],
            'DestructionPropertiesVocab-1.0':['erasurescope'],'DestructionStrategicObjectivesVocab-1.0':['destroy physical entity','destroy virtual entity'],'DestructiontacticalObjectivesVocab-1.0':
            ['erase data','destroy firmware','destroy hardware'],'FraudStrategicObjectivesVocab-1.0':['perform premium rate fraud','perform click fraud'],'FraudTacticalObjectivesVocab-1.0':
            ['access premium service'],'InfectionPropagationPropertiesVocab-1.0':['scope','infection targeting','autonomy','targeted file type','targeted file architecture type',
            'file infection type'],'InfectionPropagationStrategicObjectivesVocab-1.0':['prevent duplicate infection','infect file','infect remote machine'],'InfectionPropagationTacticalObjectivesVocab-1.0':
            ['identify file','perfrom autonomous remote infection','identify target machine(s)','perform social-engineering based remote infection','inventory victims','write code into files',
            'modify file'],'IntegrityViolationStrategicObjectivesVocab-1.0':['compromise system operational integrity','compromise user data integrity','annoy user','compromise network operational integrity',
            'compromise system data integrity'],'IntegrityViolationTacticalObjectivesVocab-1.0':['subvert system','corrupt system data','annoy local system user','intercept/manipulate network traffic',
            'annoy remote user','corrupt user data'],'MachineAccessControlPropertiesVocab-1.0':['backdoor type'],'MachineAccessControlStrategicObjectivesVocab-1.0':['control local machine','install backdoor'],
            'MachineAccessControlTacticalObjectivesVocab-1.0':['control machine via remote command'],'PersistencePropertiesVocab-1.0':['scope'],'PersistenceStrategicObjectivesVocab-1.0':
            ['persist to re-infect system','gather information for improvement','ensure compatibility','persist to continuously execute on system'],'PersistenceTacticalObjectivesVocab-1.0':
            ['reinstantiate self after initial detection','limit application type/version','persist after os install/reinstall','drop/retrieve debug log file','persist independent of hard disk/os changes',
            'persist after system reboot'],'PrivilegeEscalationPropertiesVocab-1.0':['user privilege escalation type'],'PrivilegeEscalationStrategicObjectivesVocab-1.0':['impersonate user',
            'escalate user privilege'],'PrivilegeEscalationTacticalObjectivesVocab-1.0':['elevate cpu mode'],'ProbingStrategicObjectivesVocab-1.0':['probe host configuration','probe network configuration'],
            'ProbingTacticalObjectivesVocab-1.0':['identify os','check for proxy','check for firewall','check for network drives','map local network','inventory system applications',
            'check language','check for internet connectivity'],'RemoteMachineManipulationStrategicObjectivesVocab-1.0':['access remote machine','search for remote machine'],
            'RemoteMachineManipulationTacticalObjectivesVocab-1.0':['compromise remote machine'],'SecondaryOperationPropertiesVocab-1.0':['trigger type'],'SecondaryOperationStrategicObjectivesVocab-1.0':
            ['patch operating system file(s)','remove traces of infection','log activity','lay dormant','install other components','suicide exit'],'SecondaryOperationTacticalObjectivesVocab-1.0':
            ['install secondary module','install secondary malware','install legitimate software','remove self','remove system artifacts'],'SecurityDegradationPropertiesVocab-1.0':
            ['targeted program'],'SecurityDegradationStrategicObjectivesVocab-1.0':['disable server provider security features','degrade security programs','disable system updates',
            'disable os security features','disable [host-based or os] access controls'],'SecurityDegradationTacticalObjectivesVocab-1.0':['stop execution of security program','disable firewall',
            'disable access right checking','disable kernel patching protection','prevent access to security  websites','remove sms warning messages','modify security program configuration',
            'prevent security program from running','disable system update services/daemons','disable system service pack/patch installation','disable system file overwrite protection',
            'disable privilege limiting','gather security program info','disable os security alerts','disable user account control'],'SpyingStrategicObjectivesVocab-1.0':['capture system input peripheral data',
            'capture system state data','capture system interface data','capture system output peripheral data'],'SpyingTacticalObjectivesVocab-1.0':['capture system screenshot','capture camera input',
            'capture file system','capture printer output','capture gps data','capture keyboard input','capture mouse input','capture microphone input','capture system network traffic',
            'capture touchscreen input','capture system memory'],'MalwareConfigurationParameterVocab-1.0':['magic number','id','group id','mutex','filename','installation path'],'MalwareDevelopmentToolVocab-1.0':
            ['builder','compiler','linker','packer','crypter','protector'],'MalwareSubjectRelationshipTypeVocab-1.1':['downloads','downloaded by','drops','dropped by','extracts','extracted from',
            'direct descendant of','direct ancestor of','memory image of','contained in memory image','disk image of','contained in disk image','network traffic capture of','contained in network traffic capture',
            'packed version of','unpacked version of','installs','installed by','64-bit version of','32-bit version of','encrypted version of','decrypted version of'],'GroupinRelationshipTypeVocab-1.0':
            ['same malware family','clustered together','observed together','part of intrusion set','same malware toolkit']}

maecEnumFiles={'BundleContentTypeEnum':'BundleContentTypeEnum.xml','ActionImplementationTypeEnum':'ActionImplementationTypeEnum.xml','MalwareCapabilityEnum':'MalwareCapabilityEnum.xml',
               'ObjectStateEnum':'ObjectStateEnum.xml','DataTypeEnum':'DataTypeEnum.xml','EffectTypeEnum':'EffectTypeEnum.xml','ObjectRelationshipEnum':'ObjectRelationshipEnum.xml',
               'InformationSourceTypeEnum':'InformationSourceTypeEnum.xml','ToolTypeEnum':'ToolTypeEnum.xml','HashNameEnum':'HashNameEnum.xml'}


maecBundle={'maecVocabs':maecVocabs} 




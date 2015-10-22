from apt_pkg import md5sum

__author__ = 'george'

from cybox.core import Action, ActionArguments, ActionArgument,ActionAliases,Frequency, AssociatedObjects, AssociatedObject,ActionRelationships, ActionRelationship, ActionReference
from cybox.common.measuresource import MeasureSource
from cybox.common.contributor import Contributor,Personnel
from cybox.common.daterange import DateRange
from cybox.common.time import Time as dstime
from cybox.common.hashes import Hash
from cybox.common.tools import ToolInformationList, ToolInformation
from mixbox.idgen import IDGenerator, set_id_method, set_id_namespace, create_id
from cybox.common.platform_specification import  PlatformSpecification, PlatformIdentifier
from cybox.objects.system_object import System, BIOSInfo, OS, NetworkInterface, NetworkInterfaceList, DHCPServerList,IPInfoList,IPGatewayList, IPInfo
from cybox.common.properties import Date ,Time,Duration,DateTime,String
from cybox.common.environment_variable import EnvironmentVariable, EnvironmentVariableList
from cybox.objects.address_object import Address
from cybox.common.structured_text import StructuredText
from cybox.objects.process_object import Process, ChildPIDList,ArgumentList,ImageInfo,NetworkConnectionList,PortList
from cybox.common.extracted_features import ExtractedFeatures,Functions,Imports,CodeSnippets
from cybox.common.extracted_string import ExtractedString,ExtractedStrings
from cybox.objects.code_object import Code
from cybox.objects.network_connection_object import NetworkConnection,Layer7Connections
from cybox.objects.socket_address_object import SocketAddress
from cybox.objects.port_object import Port
from cybox.objects.hostname_object import Hostname
from cybox.objects.http_session_object import HTTPSession
from  cybox.objects.dns_query_object import DNSQuery

class CyboxAction(Action):
    def __init__(self, id=None, idref=None, namespace=None,name=None,action_status=None,context=None,description=None,discovery_method=None,frequency=None,action_aliases=None,
                 action_arguments=None,ordinal_position=None,timestamp=None,type=None,associated_objects=None,relationships=None
                 ):
        super(CyboxAction, self).__init__()
        set_id_method(IDGenerator.METHOD_UUID)
        if id is None and idref is None:
            if namespace is not None:
                set_id_namespace(namespace)
            self.id_ = create_id()
        self.action_arguments = action_arguments
        self.action_aliases = action_aliases
        self.discovery_method = discovery_method
        self.name = name
        self.action_status = action_status
        self.associated_objects = associated_objects
        self.type_ = type
        self.timestamp = timestamp
        self.relationships =relationships
        self.ordinal_position = ordinal_position
        self.frequency= frequency
        self.description = description
        self.context = context

    def addrelationships(self,action_relationship):
        if not isinstance(self.relationships,ActionRelationships):
            self.relationships = ActionRelationships()
        self.relationships.append(action_relationship)

    def createactionrelationship(self,type=None,action_references=None):
        actionrelationship = ActionRelationship()
        actionrelationship.type =type
        if action_references is not None:
            for actionref in action_references:
                actionrelationship.action_references.append(actionref)
        return  actionrelationship

    def createactionreference(self,action_id=None):
        return  ActionReference(action_id=action_id)

    def addassociatedobjects(self,associated_object):
        if not isinstance(self.associated_objects,AssociatedObjects):
            self.associated_objects = AssociatedObjects()
        self.associated_objects.append(associated_object)

    def createassociatedobject(self,defined_object=None,association_type=None,type=None):
        return AssociatedObject(defined_object=defined_object,association_type=association_type)

    def addtype(self,type):
        self.type_ = type

    def addtimestamp(self,timestamp):
        self.timestamp=timestamp

    def addordinalposition(self,ordinal_position):
        self.ordinal_position=ordinal_position

    def addfrequnecy(self,rate=None,scale=None,trend=None,units=None):
        self.frequency= Frequency()
        self.frequency.rate =rate
        self.frequency.scale=scale
        self.frequency.trend=trend
        self.frequency.units=units


    def adddescription(self,description):
        self.description =description

    def addcontext(self,context):
        self.context =context

    def addactionstatus(self,action_status):
        self.action_status =action_status

    def addactionname(self,name):
        self.name=name

    def addactionargument(self, action_argument):
        if not isinstance(self.action_arguments,ActionArguments):
            self.action_arguments = ActionArguments()
        self.action_arguments.append(action_argument)

    def createactionargument(self, name, value):
        '''
        Is optional and enables the specification of a single relevant argument/parameter for this Action.
        Name must be taken from cybox.vocabs.ActionArgumentNameEnum
        '''
        action_argument = ActionArgument()
        action_argument.argument_name = name
        action_argument.argument_value = value
        return action_argument

    def addactionalias(self,action_alias):
        '''
        Adds action_alias names, enabling identification of other potentially used names for this Action.
        '''
        if not isinstance(self.action_aliases,ActionAliases):
            self.action_aliases = ActionAliases()
        self.action_aliases.append(action_alias)

    def addlocation(self):
        '''
        future implementation
        :return:
        '''
        pass

    def adddiscoverymethod(self,contributors=None,time=None,tools=None,platform=None,system=None,instance=None,description=None,source_type=None,name=None,tool_type=None,
                           sighting_count=None,information_source_type=None):
        self.discovery_method = MeasureSource()
        if contributors is not None:
            self.discovery_method.contributors = Personnel()
            for contr in contributors:
                self.discovery_method.contributors.append(contr)
        self.discovery_method.time=time
        if tools is not None:
            self.discovery_method.tools =ToolInformationList()
            for tool in tools:
                self.discovery_method.tools.append(tool)
        self.discovery_method.platform = platform
        self.discovery_method.system = system
        self.discovery_method.instance =instance
        self.discovery_method.description = description
        self.discovery_method.information_source_type=information_source_type
        self.discovery_method.sighting_count=sighting_count
        self.discovery_method.source_type = source_type
        self.discovery_method.tool_type = tool_type
        self.discovery_method.name = name

    def creatediscoverymethodcontributor(self,name=None,role=None,email=None,phone=None,organization=None,contribution_location=None,start_date=None,end_date=None):
        contributor = Contributor()
        contributor.name=name
        contributor.role = role
        contributor.email =email
        contributor.phone =phone
        contributor.organization = organization
        if start_date is not None and end_date is not None:
            if end_date > start_date:
                daterange = DateRange()
                daterange.end_date = end_date
                daterange.start_date = start_date
                contributor.date = daterange
            else:
                contributor.date =None
        contributor.contribution_location =contribution_location
        return contributor

    def creatediscoverymethodtime(self, start_time=None,end_time=None,produced_time=None,received_time=None):
        time = dstime(start_time=start_time,end_time=end_time,produced_time=produced_time,received_time=received_time)
        return time

    def creatediscoverymethodobservationlocation(self):
        '''
        future implementation
        '''
        pass

    def creatediscoverymethodtool(self,name=None,type=None,description=None,vendor=None,version=None,service_pack=None,hashes=None):
        tool = ToolInformation()
        tool.name=name
        if type is not None:
            for typename in type :
                tool.type_.append(String(value=typename))

        if description is not None:
            tool.description = StructuredText()
            tool.description.value=description
        tool.vendor =vendor
        tool.version =version
        tool.service_pack =service_pack
        if hashes is not None:
            for hashob in hashes:
                tool.tool_hashes._set_hash(hashob[0],hashob[1])
        return tool

    def creatediscoverymethodplatform(self,description=None,identifiers=None):
        platform = PlatformSpecification()
        if description is not None:
            platform.description= StructuredText(value=description)
        if not identifiers is None:
            for identifier in identifiers:
                platform.identifiers.append(identifier)
        return platform

    def creatediscoverymethodplatformidentifier(self,system=None,system_ref =None):
        identifier = PlatformIdentifier()
        identifier.system =system
        identifier.system_ref =system_ref
        return identifier

    def creatediscoverymethodsystem(self,available_physical_memory=None,bios_info=None,date=None,hostname=None,local_time=None,network_interface_list=None,os=None,processor=None,system_time=None,timezone_dst=None,
                                    timezone_standard=None,total_physical_memory=None,uptime=None,username=None):
        system = System()
        system.available_physical_memory=available_physical_memory
        system.bios_info = bios_info
        system.date = Date(value=date)
        system.hostname = hostname
        system.local_time = Time(value=local_time)
        if network_interface_list is not None:
            system.network_interface_list = NetworkInterfaceList()
            for netinter in network_interface_list:
                system.network_interface_list.append(netinter)
        system.os =os
        system.processor =processor
        system.system_time=Time(value=system_time)
        system.timezone_dst = timezone_dst
        system.timezone_standard =timezone_standard
        system.total_physical_memory=total_physical_memory
        if uptime is not None:
            system.uptime = Duration()
            system.uptime.value =uptime
        system.username = username

        return system

    def creatediscoverymethodsystembiosinfo(self,bios_date=None,manufacturer=None,bios_release_date=None,bios_serial_number =None,bios_version=None):
        bios = BIOSInfo()
        bios.bios_date = Date(value=bios_date)
        bios.bios_manufacturer=manufacturer
        bios.bios_release_date = Date(value=bios_release_date)
        bios.bios_serial_number = bios_serial_number
        bios.bios_version =bios_version
        return bios

    def creatediscoverymethodsystemos(self,bitness=None,platform=None,build_number=None,install_date=None,patch_level=None,environment_variable_list=None):
        os_obj = OS()
        os_obj.bitness =bitness
        os_obj.build_number = build_number
        if environment_variable_list is not None:
            os_obj.environment_variable_list = EnvironmentVariableList()
            for envar in environment_variable_list:
                os_obj.environment_variable_list.append(envar)
        os_obj.install_date = Date().__init__(value=install_date)
        os_obj.patch_level= patch_level
        os_obj.platform = platform # for platform creation should use creatediscoverymethodplatform
        return os_obj

    def creatediscoverymethodEnvVar(self,name=None,value=None):
        envvar = EnvironmentVariable()
        envvar.name = String(name)
        envvar.value = String(value)
        return envvar

    def creatediscoverymethodsystemnetworkinterface(self,adapter=None,description=None,dhcp_lease_expires=None,dhcp_lease_obtained=None,dhcp_server_list=None,
                                                    mac=None,ip_lst=None,ip_gateway_lst=None):
        netinter = NetworkInterface()
        netinter.adapter=adapter
        netinter.description = description
        netinter.dhcp_lease_expires = DateTime(value=dhcp_lease_expires)
        netinter.dhcp_lease_obtained =DateTime(value=dhcp_lease_obtained)
        if dhcp_server_list is not None:
            netinter.dhcp_server_list = DHCPServerList()
            for srv in dhcp_server_list :
                netinter.dhcp_server_list.append(srv)
        netinter.mac = mac
        netinter.ip_list =IPInfoList(ip_lst)

        if ip_lst is not None:
            netinter.ip_list = IPInfoList()
            for ipinf in ip_lst:
                netinter.ip_list.append(ipinf)

        if ip_gateway_lst is not None:
            netinter.ip_gateway_list= IPGatewayList()
            for gateway in ip_gateway_lst:
                netinter.ip_gateway_list.append(gateway)
        return netinter

    def creatediscoverymethodsystemnetworkinterfaceIpInfo(self,ip_address=None,ip_cat=Address.CAT_IPV4,subnet_mask=None,submaskcat=Address.CAT_IPV4_NETMASK):
        ipinf = IPInfo()
        ipinf.ip_address = Address()
        ipinf.ip_address.address_value=ip_address
        ipinf.ip_address.category = ip_cat
        ipinf.subnet_mask = Address()
        ipinf.subnet_mask.address_value = subnet_mask
        ipinf.subnet_mask.category=submaskcat
        return ipinf

    def creatediscoverymethodnetworkinerfaceAdressGateway(self,ip_address=None,ip_cat=Address.CAT_IPV4_NET):
        return Address(address_value=ip_address,category=ip_cat)

    def creatediscoverymethodnetworkinerfaceAdressDHCP(self,ip_address=None,ip_cat=Address.CAT_IPV4_NET):
        return Address(address_value=ip_address,category=ip_cat)

    def creatediscoverymethodinstance(self,argument_list=None,child_pid_list=None,creation_time =None,is_hidden=None,image_info=None,extracted_features=None,environment_variable_list=None,
                                     kernel_time=None,name=None,network_connection_list=None,parent_pid=None,pid=None,port_list=None,start_time=None,user_time=None,username=None):
        instance = Process()
        instance.argument_list= argument_list
        instance.child_pid_list=child_pid_list
        instance.creation_time = DateTime(creation_time)
        instance.username=username
        instance.user_time = Duration(user_time)
        instance.start_time = DateTime(start_time)
        instance.port_list =port_list
        instance.pid = pid
        instance.parent_pid = parent_pid
        if network_connection_list is not None and (all(isinstance(x,NetworkConnection ) for x in network_connection_list)):
            instance.network_connection_list = NetworkConnectionList()
            for netcon in network_connection_list:
                instance.network_connection_list.append(netcon)
        else:
            instance.network_connection_list= None

        instance.name = name
        instance.kernel_time = Duration(kernel_time)
        if environment_variable_list is not None and (all(isinstance(x,EnvironmentVariable ) for x in environment_variable_list)):
            instance.environment_variable_list = EnvironmentVariableList()
            for envar in environment_variable_list:
                instance.environment_variable_list.append(envar)
        else:
            instance.environment_variable_list =None

        instance.extracted_features =extracted_features
        instance.image_info = image_info
        instance.is_hidden= is_hidden
        return instance

    def creatediscoverymethodinstancechildpidlist(self,pid_list):
        cplst = ChildPIDList()
        if pid_list is not None and (all(isinstance(x, (int, long)) for x in pid_list)):
            for pidn in pid_list:
                cplst.append(pidn)
        return cplst

    def creatediscoverymethodinstanceargumentlist(self,arg_list):
        arglst = ArgumentList()
        if arg_list is not None and (all(isinstance(x,str ) for x in arg_list)):
            for argm in arg_list:
                arglst.append(argm)
        return arglst

    def creatediscoverymethodinstnaceimageingo(self,current_directory=None,command_line=None,path=None,file_name=None):
        imaginf= ImageInfo()
        imaginf.file_name=file_name
        imaginf.path=path
        imaginf.command_line = command_line
        imaginf.current_directory = current_directory
        return imaginf

    def creatediscoverymethodinstanceextractedfeautures(self,functions=None,imports=None,codesnippets=None,extractedstrings=None):
        extft = ExtractedFeatures()
        if functions is not None and (all(isinstance(x,str ) for x in functions)):
            extft.functions = Functions()
            for func in functions:
                extft.functions.append(func)

        if imports is not None and (all(isinstance(x,str ) for x in imports)):
            extft.imports = Imports()
            for imp in imports:
                extft.imports.append(imp)

        if codesnippets is not None and (all(isinstance(x,str ) for x in codesnippets)):
            extft.code_snippets = CodeSnippets()
            for codsn in codesnippets:
                code = Code()
                code.code_segment=codsn
                extft.code_snippets.append(code)

        if extractedstrings is not None and (all(isinstance(x,ExtractedString ) for x in extractedstrings)):
            extft.strings = ExtractedStrings()
            for exstr in extractedstrings:
                extft.strings.append(exstr)

        return extft

    def createextractedstring(self,string_value,address=None,byte_string_value=None,length=None,language=None,hashes=None,encoding=None,english_translation=None):
        exstr = ExtractedString(string_value=string_value)
        exstr.address = address
        exstr.byte_string_value =byte_string_value
        exstr.length =length
        exstr.language = language
        exstr.hashes = hashes
        exstr.encoding =encoding
        exstr.english_translation = english_translation
        return exstr

    def createnetworkconnection(self,creation_time=None,destination_socket_address=None,destination_tcp_state=None,source_socket_address=None,source_tcp_state=None,tls_used=None,
                                layer7_protocol=None,layer4_protocol=None,layer3_protocol=None,layer7_connections=None):
        network_connection = NetworkConnection()
        network_connection.creation_time= DateTime(creation_time)
        network_connection.destination_socket_address = destination_socket_address
        network_connection.destination_tcp_state = destination_tcp_state
        network_connection.source_socket_address = source_socket_address
        network_connection.source_tcp_state = source_tcp_state
        network_connection.tls_used =tls_used
        network_connection.layer7_protocol= layer7_protocol
        network_connection.layer4_protocol =layer4_protocol
        network_connection.layer3_protocol = layer3_protocol
        network_connection.layer7_connections = layer7_connections

        return network_connection

    def createlayer7connections(self,dns_queries=None,http_session=None):
        ls7 = Layer7Connections()
        ls7.dns_query =dns_queries
        ls7.http_session= http_session
        return  ls7

    def createsocketaddress(self,hostname,port,ip_address,ip_cat=Address.CAT_IPV4,layer4_protocol='TCP',is_domain_name=True,hostname_value=None,naming_system=None):
        socket = SocketAddress()
        socket.ip_address = Address(address_value=ip_address,category=ip_cat)
        socket.port = Port()
        socket.port.port_value=port
        socket.port.layer4_protocol =layer4_protocol
        socket.hostname = Hostname()
        socket.hostname.is_domain_name=is_domain_name
        socket.hostname.hostname_value = hostname_value
        socket.hostname.naming_system = naming_system
        return socket

    def createportlist(self,portlist):
        port_list = PortList()
        if portlist is not None:
            for port in portlist:port_list.append(port)
        return port_list


if __name__ == '__main__':
    ex = CyboxAction()
    #Add Action Type
    ex.addtype('Access')
    ###################################################################################################################
    #Add Action Name
    ex.addactionname('Accept Socket Connection')
    ###################################################################################################################
    #Add Action Description
    ex.adddescription('Example description')
    ###################################################################################################################
    #Add Action Alias
    ex.addactionalias('Add Network Share')
    ex.addactionalias('Add System Call Hook')
    ###################################################################################################################
    #Add Action Argument
    ex.addactionargument(ex.createactionargument(name='API',value='test'))
    ###################################################################################################################
    #Add Action Location
    #ex.addlocation()
    ###################################################################################################################
    #Add Discovery Method
    dmcon1 = ex.creatediscoverymethodcontributor(name='Testname1',phone='2222-333333',role='Basic',email='foo@email.com',organization='UOM',contribution_location='Thessaloniki',start_date='12/10/13',end_date='20/10/13')
    dmcon2 = ex.creatediscoverymethodcontributor(name='Testname2',phone='2222-333334',role='Admin',email='foo1@email.com',organization='UOM',contribution_location='Thessaloniki',start_date='13/10/13',end_date='20/10/13')
    import datetime,time
    dst = ex.creatediscoverymethodtime(start_time=datetime.datetime(2012, 1, 17, 8, 35, 6),end_time=datetime.datetime(2012, 2, 17, 8, 33, 6),produced_time=datetime.datetime(2012, 2, 17, 8, 40, 10),received_time=datetime.datetime(2012, 2, 17, 8, 45, 6))
    import hashlib
    tool1 = ex.creatediscoverymethodtool(hashes=[[Hash.TYPE_MD5,hashlib.md5('Testing text').hexdigest()],[Hash.TYPE_SHA1,hashlib.sha1('Testing text').hexdigest()]],name='Test tool1',
                                         description='Test tool1 example description',vendor='Test vendor 1',version='test version 1',service_pack='test SP1',type=['saddbox','debugger'])
    tool2 = ex.creatediscoverymethodtool(hashes=[[Hash.TYPE_MD5,hashlib.md5('Testing text2').hexdigest()],[Hash.TYPE_SHA1,hashlib.sha1('Testing text2').hexdigest()]],name='Test tool2',
                                         description='Test tool2 example description',vendor='Test vendor 2',version='test version 2',service_pack='test SP2',type=['saddbox','debugger1'])

    ident1 = ex.creatediscoverymethodplatformidentifier(system='win',system_ref='test refer')
    ident2 = ex.creatediscoverymethodplatformidentifier(system='unix',system_ref='test_refer2')
    pl = ex.creatediscoverymethodplatform(description='testing platform',identifiers=[ident1,ident2])

    systbios = ex.creatediscoverymethodsystembiosinfo(bios_date=datetime.datetime.now(),manufacturer='UOM',bios_release_date=datetime.datetime.now(),
                                                      bios_serial_number='test SN 12',bios_version='test version 2')

    dhcp1 = ex.creatediscoverymethodnetworkinerfaceAdressDHCP(ip_address='192.0.0.1')
    dhcp2 = ex.creatediscoverymethodnetworkinerfaceAdressDHCP(ip_address='192.0.0.2')
    ip1 = ex.creatediscoverymethodsystemnetworkinterfaceIpInfo(ip_address='192.168.2.1',subnet_mask='255.255.0.0')
    ip2 = ex.creatediscoverymethodsystemnetworkinterfaceIpInfo(ip_address='192.167.3.1',subnet_mask='255.255.255.0')
    ipgw1 = ex.creatediscoverymethodnetworkinerfaceAdressGateway(ip_address='99.0.2.1')
    ipgw2 = ex.creatediscoverymethodnetworkinerfaceAdressGateway(ip_address='99.0.2.2')
    nwl = ex.creatediscoverymethodsystemnetworkinterface(adapter='NET1234',description='Net adapt test',
                                                         dhcp_lease_expires=datetime.datetime.now() ,dhcp_lease_obtained=datetime.datetime.now(),mac='12345678',dhcp_server_list=[dhcp1,dhcp2],
                                                         ip_lst=[ip1,ip2],ip_gateway_lst=[ipgw1,ipgw2])

    syst1 = ex.creatediscoverymethodsystem(available_physical_memory=12234343,bios_info=systbios,date=datetime.datetime.now(),hostname='uom@labs',local_time=datetime.datetime.now(),
                                           system_time=time.time(),uptime=datetime.datetime.now(),username='george',network_interface_list=[nwl],processor='Intel pentium',timezone_dst='UTC',
                                           timezone_standard='UTC',total_physical_memory=555555555555)


    cpl = ex.creatediscoverymethodinstancechildpidlist([23,56,78])
    argl = ex.creatediscoverymethodinstanceargumentlist(['lls','ftp'])
    imin = ex.creatediscoverymethodinstnaceimageingo(current_directory='tmp',command_line='-h',path='C:/tmp',file_name='test.exe')
    string1= ex.createextractedstring(string_value='Test string1')
    extf= ex.creatediscoverymethodinstanceextractedfeautures(functions=['f1','f2'],imports=['im1','im2'],codesnippets=['code1','code2'],extractedstrings=[string1])
    evl1 =  ex.creatediscoverymethodEnvVar(name='Env1',value='124')
    evl2 =  ex.creatediscoverymethodEnvVar(name='Env2',value='125')

    sock1 = ex.createsocketaddress(hostname='unix1',port=84,ip_address='192.168.1.1',hostname_value='uomgr',naming_system='default')
    sock2 = ex.createsocketaddress(hostname='unix2',port=85,ip_address='192.168.1.2',hostname_value='uomg',naming_system='default')
    dnsq =DNSQuery()
    dnsq.service_used='example service1'
    dnsq1 =DNSQuery()
    dnsq1.service_used='example service2'
    l7c = ex.createlayer7connections(dns_queries=[dnsq,dnsq1],http_session=HTTPSession())
    nwc1 = ex.createnetworkconnection(creation_time=datetime.datetime.now(),destination_socket_address=sock1,source_socket_address=sock2,destination_tcp_state=502,source_tcp_state=400,
                                      tls_used='SSL',layer3_protocol='IP',layer4_protocol='TCP',layer7_protocol='HTTP',layer7_connections=l7c)
    port1 =Port()
    port1.port_value=15
    port1.layer4_protocol ='UDP'
    port2 =Port()
    port2.port_value=25
    port2.layer4_protocol ='UDP'
    prlst = ex.createportlist([port1,port2])
    inst1 = ex.creatediscoverymethodinstance(creation_time=datetime.datetime.now(),is_hidden=True,kernel_time=datetime.datetime.now(),parent_pid=124,name='Ps1',pid=304,start_time=datetime.datetime.now(),
                                             username='george',user_time=datetime.datetime.now(),child_pid_list=cpl,argument_list=argl,image_info=imin,extracted_features=extf,
                                             environment_variable_list=[evl1,evl2],network_connection_list=[nwc1],port_list=prlst)

    ex.adddiscoverymethod(contributors=[dmcon1,dmcon2],tools=[tool1,tool2],information_source_type='Application Logs',tool_type='NIPS',description='Use of Cuckoo sandbox',time=dst,platform= pl,
                          system=syst1,instance=inst1,name='testing cuckoo method',sighting_count=15,source_type='Comm Logs')
    ###################################################################################################################
    #Add Action Status
    ex.addactionstatus(action_status='Success')
    ###################################################################################################################
    #Add Action Context
    ex.addcontext(context='Host')
    ###################################################################################################################
    #Add timestamp
    ex.addtimestamp(timestamp=datetime.datetime.now())
    ###################################################################################################################
    #Add Ordinal Position
    ex.addordinalposition(15)
    ###################################################################################################################
    #Add Associated objects
    from cybox.objects.product_object import Product
    from cybox.common.vocabs import ActionObjectAssociationType
    at = ActionObjectAssociationType()
    at.value = ActionObjectAssociationType.TERM_AFFECTED
    dobj = Product()
    dobj.product='TestProduct'
    ob1 = ex.createassociatedobject(defined_object=dobj,association_type=at)
    ex.addassociatedobjects(associated_object=ob1)
    ###################################################################################################################
    # Add Frequency
    ex.addfrequnecy(rate=15,scale=18,trend=7,units=19)
    ###################################################################################################################
    # Add Relationships
    from cybox.common.vocabs import ActionRelationshipType
    ar= ActionRelationship()
    ar.value = ActionRelationshipType.TERM_INITIATED
    rf1 = ex.createactionreference(action_id='test1d:1234')
    rel1 = ex.createactionrelationship(action_references=[rf1],type=ar)
    ex.addrelationships(action_relationship=rel1)
    ###################################################################################################################

    print(ex.to_xml())
    
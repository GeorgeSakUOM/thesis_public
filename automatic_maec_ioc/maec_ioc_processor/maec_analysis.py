__author__ = 'george'
from maec.package import Analysis,Source,Comment,CommentList,DynamicAnalysisMetadata,AnalysisEnvironment, HypervisorHostSystem,AnalysisSystem,AnalysisSystemList,NetworkInfrastructure,CapturedProtocol
from mixbox.idgen import IDGenerator,create_id,set_id_method,set_id_namespace
from cybox.common.contributor import Contributor,Personnel
from cybox.common.daterange import DateRange
from cybox.common.tools import ToolInformation
from cybox.common.properties import String,Date,Time,Duration,DateTime
from cybox.common.structured_text import StructuredText
from cybox.objects.system_object import NetworkInterfaceList,BIOSInfo,OS,NetworkInterface,IPInfoList,IPGatewayList,DHCPServerList,IPInfo
from cybox.common.environment_variable import EnvironmentVariable,EnvironmentVariableList
from cybox.common.platform_specification import PlatformIdentifier,PlatformSpecification
from cybox.objects.address_object import Address

class MaecAnalysis(Analysis):

    def __init__(self,id=None,namespace=None,method=None,type=None,source=None,ordinal_position=None,
                 start_datetime=None,complete_datetime=None,lastupdate_datetime=None,analysts=None,summary=None,comments=None,tools=None,
                 dynamic_analysis_metadata=None,report=None,analysis_environment=None):
        super(MaecAnalysis,self).__init__(id=id,method=method,type=type)
        set_id_method(IDGenerator.METHOD_UUID)
        if id is None:
            if namespace is not None:
                set_id_namespace(namespace)
            self.id_ = create_id(prefix='analysis')

        self.ordinal_position=ordinal_position
        self.start_datetime=start_datetime
        self.complete_datetime =complete_datetime
        self.lastupdate_datetime =lastupdate_datetime
        self.source=source
        if analysts is not None:
            self.analysts = Personnel()
            for contr in analysts():
                if isinstance(contr,Contributor):
                    self.analysts.append(contr)
        self.summary =summary
        if comments is not None:
            self.comments = CommentList()
            for comment in comments:
                self.comments.append(comment)
        if tools is not None:
            for tool in tools:
                if isinstance(tool,ToolInformation):
                    self.add_tool(tool)
        if dynamic_analysis_metadata is not None and isinstance(dynamic_analysis_metadata,DynamicAnalysisMetadata):
            self.dynamic_analysis_metadata =dynamic_analysis_metadata
        self.report =report
        if isinstance(analysis_environment,AnalysisEnvironment):
            self.analysis_environment=analysis_environment

    def add_type(self,type=None):
        self.type_=type

    def add_method(self,method=None):
        self.method =method

    def add_ordinal_position(self,ordinal_position=None):
        self.ordinal_position=ordinal_position

    def addanalysisdatesinfo(self,start_datetime=None,complete_datetime=None,lastupdate_datetime=None):
        self.start_datetime=start_datetime
        self.complete_datetime =complete_datetime
        self.lastupdate_datetime=lastupdate_datetime

    def addsource(self,url=None,reference=None,organization=None,name=None,method=None):
        source = Source()
        source.url = url
        source.reference = reference
        source.organization = organization
        source.name = name
        source.method = method
        self.source =source

    def addanalysts(self,analysts=None):
        if not isinstance(self.analysts,Personnel):
            self.analysts = Personnel()
        for contr in analysts:
            if isinstance(contr,Contributor):
                self.analysts.append(contr)

    def createanalystscontributor(self,name=None,role=None,email=None,phone=None,organization=None,contribution_location=None,start_date=None,end_date=None):
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

    def addsummary(self,summary=None):
        self.summary=summary

    def addcomment(self,comment=None):
        if not isinstance(self.comments,CommentList):
            self.comments = CommentList()
        if isinstance(comment,Comment):
            self.comments.append(comment)

    def createcomment(self,author=None,value=None,timestamp=None,observation_name=None):
        comment = Comment()
        comment.author =author
        comment.value=value
        comment.timestamp=timestamp
        comment.observation_name=observation_name
        return comment

    def addfindingsbundlereference(self,bundle_id=None):
        self.set_findings_bundle(bundle_id=bundle_id)

    def createanalysistool(self,name=None,type=None,description=None,vendor=None,version=None,service_pack=None,hashes=None):
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

    def adddynamicanalysismetadata(self,metadata=None):
            if isinstance(metadata,DynamicAnalysisMetadata):
                self.dynamic_analysis_metadata=metadata

    def createdynamicanalysismetadata(self,exit_code=None,command_line=None,analysis_duration=None):
        metadata = DynamicAnalysisMetadata()
        metadata.exit_code =exit_code
        metadata.command_line =command_line
        metadata.analysis_duration = analysis_duration
        return metadata

    def addreport(self,report=None):
        self.report=report

    def addanalysisenvironment(self,analysis_environment=None):
        if isinstance(analysis_environment,AnalysisEnvironment):
            self.analysis_environment=analysis_environment

    def createanalysisenvironment(self,analysis_systems=None,network_infrastructure_captured_protocols=None,hypervisor_host_system=None):
        analysis_environment = AnalysisEnvironment()
        analysis_environment.network_infrastructure=NetworkInfrastructure()
        for capt_prot in network_infrastructure_captured_protocols:
            if isinstance(capt_prot,CapturedProtocol):
                analysis_environment.network_infrastructure.captured_protocols.append(capt_prot)
        analysis_environment.hypervisor_host_system=hypervisor_host_system
        analysis_environment.analysis_systems =AnalysisSystemList()
        if analysis_systems is not None:
            for analysis_system in analysis_systems:
                if isinstance(analysis_system,AnalysisSystem):
                    analysis_environment.analysis_systems.append(analysis_system)
        return analysis_environment

    def createanalysisenvironmentHVhostsystem(self,available_physical_memory=None,bios_info=None,date=None,hostname=None,local_time=None,network_interface_list=None,os=None,processor=None,system_time=None,timezone_dst=None,
                                    timezone_standard=None,total_physical_memory=None,uptime=None,username=None,vm_hypervisor=None):
        system = HypervisorHostSystem()
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
        system.vm_hypervisor=vm_hypervisor
        return system

    def createanalysisenvironmentsystembiosinfo(self,bios_date=None,manufacturer=None,bios_release_date=None,bios_serial_number =None,bios_version=None):
        bios = BIOSInfo()
        bios.bios_date = Date(value=bios_date)
        bios.bios_manufacturer=manufacturer
        bios.bios_release_date = Date(value=bios_release_date)
        bios.bios_serial_number = bios_serial_number
        bios.bios_version =bios_version
        return bios

    def createanalysisenvironmentsystemos(self,bitness=None,platform=None,build_number=None,install_date=None,patch_level=None,environment_variable_list=None):
        os_obj = OS()
        os_obj.bitness =bitness
        os_obj.build_number = build_number
        if environment_variable_list is not None:
            os_obj.environment_variable_list = EnvironmentVariableList()
            for envar in environment_variable_list:
                os_obj.environment_variable_list.append(envar)
        os_obj.install_date = Date(value=install_date)
        os_obj.patch_level= patch_level
        os_obj.platform = platform # for platform creation should use creatediscoverymethodplatform
        return os_obj


    def createanalysisenvironmentsystemEnvVar(self,name=None,value=None):
        envvar = EnvironmentVariable()
        envvar.name = String(name)
        envvar.value = String(value)
        return envvar

    def createanalysisenvironmentsystemnetworkinterface(self,adapter=None,description=None,dhcp_lease_expires=None,dhcp_lease_obtained=None,dhcp_server_list=None,
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

    def createanalysisenvironmentsystemnetworkinterfaceIpInfo(self,ip_address=None,ip_cat=Address.CAT_IPV4,subnet_mask=None,submaskcat=Address.CAT_IPV4_NETMASK):
        ipinf = IPInfo()
        ipinf.ip_address = Address()
        ipinf.ip_address.address_value=ip_address
        ipinf.ip_address.category = ip_cat
        ipinf.subnet_mask = Address()
        ipinf.subnet_mask.address_value = subnet_mask
        ipinf.subnet_mask.category=submaskcat
        return ipinf

    def createanalysisenvironmentsystemnetworkinerfaceAdressGateway(self,ip_address=None,ip_cat=Address.CAT_IPV4_NET):
        return Address(address_value=ip_address,category=ip_cat)

    def createanalysisenvironmentsystemnetworkinerfaceAdressDHCP(self,ip_address=None,ip_cat=Address.CAT_IPV4_NET):
        return Address(address_value=ip_address,category=ip_cat)

    def createanalysisenvironmentsystemplatform(self,description=None,identifiers=None):
        platform = PlatformSpecification()
        if description is not None:
            platform.description= StructuredText(value=description)
        if not identifiers is None:
            for identifier in identifiers:
                platform.identifiers.append(identifier)
        return platform

    def createanalysisenvironmentsystemplatformidentifier(self,system=None,system_ref =None):
        identifier = PlatformIdentifier()
        identifier.system =system
        identifier.system_ref =system_ref
        return identifier


    def createanalysisenvironmentanalysissystem(self,installed_programs=None,network_interfaces=None):
        analysis_system=AnalysisSystem()
        for program in installed_programs:
            if isinstance(program,PlatformSpecification):
                analysis_system.installed_programs.append(program)
        analysis_system.network_interface_list=NetworkInterfaceList()
        for nw in network_interfaces:
            if isinstance(nw,NetworkInterface):
                analysis_system.network_interface_list.append(nw)
        return analysis_system

    def createanalysisenvironmentnetworkinfrastructurecapturedprotocol(self,port_number=None,layer7_protocol=None,layer4_protocol=None,interaction_level=None):
        protocol = CapturedProtocol()
        protocol.port_number= port_number
        protocol.layer7_protocol=layer7_protocol
        protocol.layer4_protocol=layer4_protocol
        protocol.interaction_level = interaction_level
        return protocol

if __name__=='__main__':
    #Testing example
    from mixbox.namespaces import Namespace
    an_ex = MaecAnalysis(namespace=Namespace('testnamespace','totest','testschemalocation'))
    ####################################################################################################################
    #Add type
    an_ex.add_type('triage')
    ####################################################################################################################
    #Add method
    an_ex.add_method(method='dynamic')
    ####################################################################################################################
    #Add Ordinal Position
    an_ex.add_ordinal_position(ordinal_position=15)
    ####################################################################################################################
    #Add analysis dates info
    import datetime
    an_ex.addanalysisdatesinfo(start_datetime=datetime.datetime.now(),complete_datetime=datetime.datetime.now(),
                               lastupdate_datetime=datetime.datetime.now())
    ####################################################################################################################
    #Add analysts
    con1 = an_ex.createanalystscontributor(name='Testname1',phone='2222-333333',role='Basic',email='foo@email.com',
                                           organization='UOM',contribution_location='Thessaloniki',start_date='12/10/13',end_date='20/10/13')
    con2 = an_ex.createanalystscontributor(name='Testname2',phone='2222-333334',role='Admin',email='foo1@email.com',
                                           organization='UOM',contribution_location='Thessaloniki',start_date='13/10/13',end_date='20/10/13')
    an_ex.addanalysts([con1,con2])
    #Add source
    an_ex.addsource(url='http://testingurl',reference='Testing reference',organization='Testing organization',name='TestName',method='Testmethod')
    ####################################################################################################################
    #Add summary
    an_ex.addsummary(summary='Testing summary')
    ####################################################################################################################
    #Add comment
    com1 = an_ex.createcomment(author='Test author1',value='Testing comment 1',timestamp=datetime.datetime.now(),observation_name='Observation Name 1')
    an_ex.addcomment(com1)
    com2 = an_ex.createcomment(author='Test author2',value='Testing comment 2',timestamp=datetime.datetime.now(),observation_name='Observation Name 2')
    an_ex.addcomment(com2)
    ####################################################################################################################
    #Add findings bundle reference
    an_ex.addfindingsbundlereference(bundle_id='testidref')
    ####################################################################################################################
    #Add tool
    from cybox.common.hashes import Hash
    import hashlib
    tool1 = an_ex.createanalysistool(hashes=[[Hash.TYPE_MD5,hashlib.md5('Testing text').hexdigest()],[Hash.TYPE_SHA1,hashlib.sha1('Testing text').hexdigest()]],name='Test tool1',
                                         description='Test tool1 example description',vendor='Test vendor 1',version='test version 1',service_pack='test SP1',type=['saddbox','debugger'])
    an_ex.add_tool(tool1)
    ####################################################################################################################
    #Add dynamic analysis metadata
    metadata = an_ex.createdynamicanalysismetadata(exit_code=25,command_line='testing command line',analysis_duration=150000.555)
    an_ex.adddynamicanalysismetadata(metadata)
    ####################################################################################################################
    #Add report
    an_ex.addreport(report='Testing report')
    ####################################################################################################################
    #Add analysis environment
    import time
    ident1 = an_ex.createanalysisenvironmentsystemplatformidentifier(system='win',system_ref='test refer')
    ident2 = an_ex.createanalysisenvironmentsystemplatformidentifier(system='unix',system_ref='test_refer2')
    pl1 = an_ex.createanalysisenvironmentsystemplatform(description='testing platform',identifiers=[ident1,ident2])

    systbios = an_ex.createanalysisenvironmentsystembiosinfo(bios_date=datetime.datetime.now(),manufacturer='UOM',bios_release_date=datetime.datetime.now(),
                                                      bios_serial_number='test SN 12',bios_version='test version 2')
    evl3 =  an_ex.createanalysisenvironmentsystemEnvVar(name='Env1',value='13')
    evl4 =  an_ex.createanalysisenvironmentsystemEnvVar(name='Env2',value='14')

    os1 = an_ex.createanalysisenvironmentsystemos(platform=pl1,build_number='testbuildnumber',install_date=datetime.datetime.now(),patch_level='top',environment_variable_list=[evl3,evl4])


    dhcp1 = an_ex.createanalysisenvironmentsystemnetworkinerfaceAdressDHCP(ip_address='192.0.0.1')
    dhcp2 = an_ex.createanalysisenvironmentsystemnetworkinerfaceAdressDHCP(ip_address='192.0.0.2')
    ip1 = an_ex.createanalysisenvironmentsystemnetworkinterfaceIpInfo(ip_address='192.168.2.1',subnet_mask='255.255.0.0')
    ip2 = an_ex.createanalysisenvironmentsystemnetworkinterfaceIpInfo(ip_address='192.167.3.1',subnet_mask='255.255.255.0')
    ipgw1 = an_ex.createanalysisenvironmentsystemnetworkinerfaceAdressGateway(ip_address='99.0.2.1')
    ipgw2 = an_ex.createanalysisenvironmentsystemnetworkinerfaceAdressGateway(ip_address='99.0.2.2')
    nwl = an_ex.createanalysisenvironmentsystemnetworkinterface(adapter='NET1234',description='Net adapt test',
                                                         dhcp_lease_expires=datetime.datetime.now() ,dhcp_lease_obtained=datetime.datetime.now(),mac='12345678',dhcp_server_list=[dhcp1,dhcp2],
                                                         ip_lst=[ip1,ip2],ip_gateway_lst=[ipgw1,ipgw2])

    ident7 = an_ex.createanalysisenvironmentsystemplatformidentifier(system='win11',system_ref='test refer7')
    ident8 = an_ex.createanalysisenvironmentsystemplatformidentifier(system='unix33',system_ref='test_refer8')
    pl4 = an_ex.createanalysisenvironmentsystemplatform(description='testing platform',identifiers=[ident7,ident8])
    hvhostsyst1 = an_ex.createanalysisenvironmentHVhostsystem(available_physical_memory=12234343,bios_info=systbios,date=datetime.datetime.now(),hostname='uom@labs',local_time=datetime.datetime.now(),
                                           system_time=time.time(),uptime=datetime.datetime.now(),username='george',network_interface_list=[nwl],processor='Intel pentium',timezone_dst='UTC',
                                           timezone_standard='EET',total_physical_memory=555555555555,os=os1,vm_hypervisor=pl4)

    ident3 = an_ex.createanalysisenvironmentsystemplatformidentifier(system='win1',system_ref='test refer3')
    ident4 = an_ex.createanalysisenvironmentsystemplatformidentifier(system='unix1',system_ref='test_refer4')
    pl2 = an_ex.createanalysisenvironmentsystemplatform(description='testing platform',identifiers=[ident3,ident4])
    ident5 = an_ex.createanalysisenvironmentsystemplatformidentifier(system='win10',system_ref='test refer5')
    ident6 = an_ex.createanalysisenvironmentsystemplatformidentifier(system='unix2',system_ref='test_refer6')
    pl3 = an_ex.createanalysisenvironmentsystemplatform(description='testing platform',identifiers=[ident5,ident6])
    analysis_system = an_ex.createanalysisenvironmentanalysissystem(installed_programs=[pl2,pl3])

    prot1 = an_ex.createanalysisenvironmentnetworkinfrastructurecapturedprotocol(port_number=25,layer7_protocol='http',layer4_protocol='tcp',interaction_level='high')
    prot2 = an_ex.createanalysisenvironmentnetworkinfrastructurecapturedprotocol(port_number=25,layer7_protocol='https',layer4_protocol='udp',interaction_level='low')

    analysis_environment=an_ex.createanalysisenvironment(hypervisor_host_system=hvhostsyst1,analysis_systems=[analysis_system],network_infrastructure_captured_protocols=[prot1,prot2])

    an_ex.addanalysisenvironment(analysis_environment)
    #Printing results
    print(an_ex.to_xml())
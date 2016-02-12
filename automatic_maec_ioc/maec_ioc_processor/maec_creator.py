'''
@author: george
'''
import os
import json
import datetime
from common.configmanager import ConfigurationManager
#from maec_ioc_processor.maec_bundle_files.maec_bundle_files import MaecBundle
from maec_ioc_processor.maec_package import MaecPackage
#from maec_ioc_processor.maec_container import  MAECContainer
from maec_ioc_processor.cuckoo_results_handler import AnalysisHandler
from maec_ioc_processor.maec_malware_subject import MaecMalwareSubject
from maec_ioc_processor.maec_analysis import MaecAnalysis
from mixbox.namespaces import Namespace
from cybox_object import CyboxObject
from cybox.common.hashes import Hash

PREFIX='ioc_generator'
SCHEMA_LOCATION = 'schema_location'
NAMESPACE = 'ioc_namespace'
SUMMARY = 'This analysis was produced from the IoCs Generator System.'
BUNDLES_PATH = ConfigurationManager.readmaecConfig(variable='maec_path_bundles')
PACKAGES_PATH = ConfigurationManager.readmaecConfig(variable='maec_path_packages')
CONTAINERS_PATH = ConfigurationManager.readmaecConfig(variable='maec_path_containers')
XML_PATH=ConfigurationManager.readxmlConfig(variable='xml_path')
#
#Testing methods
from maec_ioc_processor.cuckoo_results_handler import load_results
from maec_ioc_processor.maec_bundle import MaecBundle
#
def load_xml_filenames_dictionary():
    with open(os.path.join(XML_PATH,'files_dictionary.json'),'r') as jsonfile:
        dictfile = jsonfile.read()
        filesdict= json.loads(dictfile)
        jsonfile.close()
    return filesdict

class MAECCreator(object):

    def __init__(self, results,bundles_path=BUNDLES_PATH,packages_path=PACKAGES_PATH,containers_path=CONTAINERS_PATH):
        self.bundles_path =bundles_path
        self.packages_path = packages_path
        self.containers_path = containers_path
        self.results =results
        self.analysis_handler=AnalysisHandler(data_results=results)
        self.xml_files_dict = load_xml_filenames_dictionary()
        self.namespace = Namespace(NAMESPACE,PREFIX,SCHEMA_LOCATION)

class MAECPackageCreator(MAECCreator):

    def __init__(self,results):
        super(MAECPackageCreator,self).__init__(results)
        self.package =MaecPackage()

    def return_package(self):
        return self.package.to_xml()

class MAECMalwareSubjectCreator(MAECCreator):

    def __init__(self,results):
        super(MAECMalwareSubjectCreator,self).__init__(results)
        self.subject = MaecMalwareSubject(namespace=self.namespace)
        self.bind_analysis_info()
        self.bind_targetinfo()
        self.bind_virustotal()
        self.bind_analysis()

    def return_malware_subject(self):
        return self.subject.to_xml()

    def bind_analysis_info(self):
        analysis_info_simple_values= self.analysis_handler.analysisinfo.get_section_simple_values()
        analysis_machine = self.analysis_handler.analysisinfo.get_machine()
        self.analysis = MaecAnalysis(namespace=self.namespace,start_datetime=analysis_info_simple_values['started'],complete_datetime=analysis_info_simple_values['ended'])
        self.analysis.add_method('dynamic')
        self.analysis.add_type('triage')
        self.analysis.add_ordinal_position(1)
        self.analysis.addsource(method='IoCs Generator System',name='George Sakellariou',organization='UOM')
        analyst = self.analysis.createanalystscontributor(name='infosec',organization='UOM',contribution_location='Thessaloniki,Greece',
                                                          role='administrator',start_date='1/1/2016',end_date=str(datetime.date.today()),phone='+302310891868',
                                                          email='mai1428@uom.edu.gr')
        self.analysis.addanalysts([analyst])
        self.analysis.addsummary(SUMMARY)
        tool = self.analysis.createanalysistool(name='Cuckoo Sandbox',type=['sandbox'],description='Cuckoo is an open source automated malware analysis system',
                                                vendor='Cuckoo Foundation',version=analysis_info_simple_values['version'],hashes=[['SHA1','da9866085efe9ef614e7577d8a88922da8b2c670']])
        self.analysis.add_tool(tool)
        metadata = self.analysis.createdynamicanalysismetadata(analysis_duration=analysis_info_simple_values['duration'])
        self.analysis.adddynamicanalysismetadata(metadata)
        ip = self.analysis.createanalysisenvironmentsystemnetworkinterfaceIpInfo(ip_address='192.168.56.1',subnet_mask='255.255.255.0')
        ip_gateway = self.analysis.createanalysisenvironmentsystemnetworkinerfaceAdressGateway(ip_address='192.168.56.1')
        network_interface = self.analysis.createanalysisenvironmentsystemnetworkinterface(description='vboxnet0',dhcp_server_list=[],ip_lst=[ip],ip_gateway_lst=[ip_gateway])
        os_platform_identifier = self.analysis.createanalysisenvironmentsystemplatformidentifier(system='cpe:/o:canonical:ubuntu_linux:14.04:-:lts',
                                                                                                 system_ref='https://cpe.mitre.org/specification/2.2/cpe-dictionary_2.2.xsd')
        os_platform = self.analysis.createanalysisenvironmentsystemplatform(description='Ubuntu 14.04.3 LTS',identifiers=[os_platform_identifier])
        os = self.analysis.createanalysisenvironmentsystemos(platform=os_platform,bitness='64')
        vm_hypervisor_identifier=self.analysis.createanalysisenvironmentsystemplatformidentifier(system='cpe:/a:oracle:vm_virtualbox:4.3.34',system_ref='https://cpe.mitre.org/specification/2.2/cpe-dictionary_2.2.xsd')
        vm_hypervisor =self.analysis.createanalysisenvironmentsystemplatform(description=analysis_machine['manager'],identifiers=[vm_hypervisor_identifier])
        HVhostsystem = self.analysis.createanalysisenvironmentHVhostsystem(hostname='analyzer',username='analyzer',vm_hypervisor=vm_hypervisor,
                                                                           os=os,network_interface_list=[network_interface],timezone_standard='EET',)

        ipvm = self.analysis.createanalysisenvironmentsystemnetworkinterfaceIpInfo(ip_address='192.168.56.101',subnet_mask='255.255.255.0')
        ip_gatewayvm = self.analysis.createanalysisenvironmentsystemnetworkinerfaceAdressGateway(ip_address='192.168.56.1')
        network_interfacevm = self.analysis.createanalysisenvironmentsystemnetworkinterface(adapter='PCnet_FAST III',
                                                                                         description='vboxnet0',dhcp_server_list=[],ip_lst=[ipvm],ip_gateway_lst=[ip_gatewayvm])

        os_platform_identifier_vm = self.analysis.createanalysisenvironmentsystemplatformidentifier(system='cpe:/o:microsoft:windows_xp::sp1:home',
                                                                                                 system_ref='https://cpe.mitre.org/specification/2.2/cpe-dictionary_2.2.xsd')
        os_platform_vm = self.analysis.createanalysisenvironmentsystemplatform(description='Windows XP',identifiers=[os_platform_identifier_vm])
        osvm = self.analysis.createanalysisenvironmentsystemos(platform=os_platform_vm,bitness='32')
        inetsim_identifier= self.analysis.createanalysisenvironmentsystemplatformidentifier(system='cpe:/a:inetsim:inetsim:1.2.5',
                                                                                                 system_ref='https://cpe.mitre.org/specification/2.2/cpe-dictionary_2.2.xsd')
        inetsim = self.analysis.createanalysisenvironmentsystemplatform(description='INetSim',identifiers=[inetsim_identifier])
        analysis_system = self.analysis.createanalysisenvironmentanalysissystem(installed_programs=[inetsim],network_interfaces=[network_interfacevm])
        analysis_system.username=analysis_machine['name']
        analysis_system.hostname=analysis_machine['label']
        analysis_system.os=osvm
        analysis_system.available_physical_memory=512000000
        analysis_system.timezone_standard='EET'
        analysis_system.local_time = analysis_machine['shutdown_on']
        protocol1=self.analysis.createanalysisenvironmentnetworkinfrastructurecapturedprotocol(port_number=53,layer7_protocol='dns',layer4_protocol='udp',interaction_level='honeytrap')
        protocol2=self.analysis.createanalysisenvironmentnetworkinfrastructurecapturedprotocol(port_number=80,layer7_protocol='http',layer4_protocol='tcp',interaction_level='honeytrap')
        protocol3=self.analysis.createanalysisenvironmentnetworkinfrastructurecapturedprotocol(port_number=443,layer7_protocol='https',layer4_protocol='tcp',interaction_level='honeytrap')
        protocol4=self.analysis.createanalysisenvironmentnetworkinfrastructurecapturedprotocol(port_number=25,layer7_protocol='smtp',layer4_protocol='tcp',interaction_level='honeytrap')
        protocol5=self.analysis.createanalysisenvironmentnetworkinfrastructurecapturedprotocol(port_number=465,layer7_protocol='smtps',layer4_protocol='tcp',interaction_level='honeytrap')
        protocol6=self.analysis.createanalysisenvironmentnetworkinfrastructurecapturedprotocol(port_number=110,layer7_protocol='pop3',layer4_protocol='tcp',interaction_level='honeytrap')
        protocol7=self.analysis.createanalysisenvironmentnetworkinfrastructurecapturedprotocol(port_number=995,layer7_protocol='pop3s',layer4_protocol='tcp',interaction_level='honeytrap')
        protocol8=self.analysis.createanalysisenvironmentnetworkinfrastructurecapturedprotocol(port_number=69,layer7_protocol='tftp',layer4_protocol='tcp',interaction_level='honeytrap')
        protocol9=self.analysis.createanalysisenvironmentnetworkinfrastructurecapturedprotocol(port_number=21,layer7_protocol='ftp',layer4_protocol='tcp',interaction_level='honeytrap')
        protocol10=self.analysis.createanalysisenvironmentnetworkinfrastructurecapturedprotocol(port_number=123,layer7_protocol='ntp',layer4_protocol='tcp',interaction_level='honeytrap')
        protocol11=self.analysis.createanalysisenvironmentnetworkinfrastructurecapturedprotocol(port_number=990,layer7_protocol='ftps',layer4_protocol='tcp',interaction_level='honeytrap')
        protocol12=self.analysis.createanalysisenvironmentnetworkinfrastructurecapturedprotocol(port_number=6667,layer7_protocol='irc',layer4_protocol='tcp',interaction_level='honeytrap')
        protocol13=self.analysis.createanalysisenvironmentnetworkinfrastructurecapturedprotocol(port_number=37,layer7_protocol='time',layer4_protocol='tcp',interaction_level='honeytrap')
        protocol14=self.analysis.createanalysisenvironmentnetworkinfrastructurecapturedprotocol(port_number=13,layer7_protocol='daytime',layer4_protocol='tcp',interaction_level='honeytrap')
        protocol15=self.analysis.createanalysisenvironmentnetworkinfrastructurecapturedprotocol(port_number=7,layer7_protocol='echo',layer4_protocol='tcp',interaction_level='honeytrap')
        protocol16=self.analysis.createanalysisenvironmentnetworkinfrastructurecapturedprotocol(port_number=9,layer7_protocol='discard',layer4_protocol='tcp',interaction_level='honeytrap')
        protocol17=self.analysis.createanalysisenvironmentnetworkinfrastructurecapturedprotocol(port_number=17,layer7_protocol='quotd',layer4_protocol='tcp',interaction_level='honeytrap')
        protocol18=self.analysis.createanalysisenvironmentnetworkinfrastructurecapturedprotocol(port_number=19,layer7_protocol='chargen',layer4_protocol='tcp',interaction_level='honeytrap')
        protocol19=self.analysis.createanalysisenvironmentnetworkinfrastructurecapturedprotocol(port_number=79,layer7_protocol='finger',layer4_protocol='tcp',interaction_level='honeytrap')
        protocol20=self.analysis.createanalysisenvironmentnetworkinfrastructurecapturedprotocol(port_number=113,layer7_protocol='ident',layer4_protocol='tcp',interaction_level='honeytrap')
        protocol21=self.analysis.createanalysisenvironmentnetworkinfrastructurecapturedprotocol(port_number=514,layer7_protocol='syslog',layer4_protocol='tcp',interaction_level='honeytrap')
        protocol22=self.analysis.createanalysisenvironmentnetworkinfrastructurecapturedprotocol(port_number=1,layer7_protocol='dummy',layer4_protocol='tcp',interaction_level='honeytrap')

        analysis_environment= self.analysis.createanalysisenvironment(hypervisor_host_system=HVhostsystem,analysis_systems=[analysis_system],
                                                                      network_infrastructure_captured_protocols=[protocol1,protocol10,protocol11,protocol12,protocol13,
                                                                                                                 protocol14,protocol15,protocol16,protocol17,protocol18,
                                                                                                                 protocol19,protocol20,protocol21,protocol22,protocol2,
                                                                                                                 protocol3,protocol4,protocol5,protocol6,protocol7,
                                                                                                                 protocol8,protocol9])
        self.analysis.addanalysisenvironment(analysis_environment)


    def bind_procmemory(self):
        pass
    def bind_static(self):
        pass
    def bind_dropped(self):
        pass
    def bind_behavior(self):
        pass
    def bind_strings(self):
        pass
    def bind_debug(self):
        pass
    def bind_memory(self):
        pass
    def bind_targetinfo(self):
        objecttype=None
        target_info_simple_values = self.analysis_handler.targetinfo.get_section_simple_values()
        if target_info_simple_values['category']=='file':
            objecttype=CyboxObject().objecttype
            file_infos = self.analysis_handler.targetinfo.get_file()
            objecttype.file_name = file_infos['name']
            objecttype.device_path = os.path.dirname(file_infos['path'])
            objecttype.full_path = file_infos['path']
            objecttype.size_in_bytes = file_infos['size']
            objecttype.file_extension = '.'.join(file_infos['name'].split('.')[1:])
            objecttype.file_format = file_infos['type']
            objecttype.add_hash(Hash(hash_value=file_infos['crc32'],type_=Hash.TYPE_OTHER))
            objecttype.add_hash(Hash(hash_value=file_infos['md5'],type_=Hash.TYPE_MD5))
            objecttype.add_hash(Hash(hash_value=file_infos['sha1'],type_=Hash.TYPE_SHA1))
            objecttype.add_hash(Hash(hash_value=file_infos['sha256'],type_=Hash.TYPE_SHA256))
            objecttype.add_hash(Hash(hash_value=file_infos['sha512'],type_=Hash.TYPE_SHA512))
            objecttype.add_hash(Hash(hash_value=file_infos['ssdeep'],type_=Hash.TYPE_SSDEEP))
        else:
            pass
            #TODO when category is URI
        self.subject.addmalwareinstanceobjectattributes(objecttype)

    def bind_virustotal(self):
        self.bundle = MaecBundle()
        scans= self.analysis_handler.virustotal.get_section_simple_values()['scans']
        engines = scans.keys()
        while scans:
            engine = engines.pop()
            data = scans.pop(engine)
            av_classification = self.bundle.create_av_classification(classification=data['result'],tool_name=engine,
                                                                     engine_version=data['version'],definition_version=data['update'])
            self.bundle.add_av_classification(av_classification)

    def bind_network(self):
        pass
    def bind_analysis(self):
        self.subject.add_analysis(self.analysis)
        self.subject.addbundleinfindingbundles(self.bundle)


if __name__=='__main__':
    results = load_results('cuckoo_results')
    # Testing
    mc = MAECMalwareSubjectCreator(results)
    print(mc.return_malware_subject())
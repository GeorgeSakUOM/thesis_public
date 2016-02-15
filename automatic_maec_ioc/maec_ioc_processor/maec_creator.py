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
from cybox.common.hashes import Hash,HashList
from cybox.objects.win_executable_file_object import WinExecutableFile,PEExports,PEExportedFunction,\
    PEExportedFunctions,PEImportedFunctions,PEImportList,PEImport,PEImportedFunction,PESection,PESectionHeaderStruct,\
    PESectionList,Entropy,PEResourceList,PEResource,PEVersionInfoResource,PEHeaders,PEFileHeader
from cybox.common.extracted_features import ExtractedFeatures
from cybox.common.extracted_string import ExtractedString,ExtractedStrings
from langdetect import detect
import hashlib
from maec.bundle import ObjectList
from maec.bundle.process_tree import ProcessTree,ProcessTreeNode
from cybox.objects.process_object import ChildPIDList
from cybox.common import DateTime
import datetime
from maec_bundle_action import MaecBundleAction
from cybox.core import AssociatedObject,AssociatedObjects
from cybox.objects.win_thread_object import WinThread
from cybox.objects.process_object import ImageInfo

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
        self.bind_static()
        self.bind_targetinfo()
        self.bind_virustotal()
        self.bind_dropped()
        self.bind_behavior()
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


    def bind_procmemory(self,root_process):
        procmemory=self.analysis_handler.procmemory.list
        if procmemory:
            proc_dict={}
            for proc in procmemory:
                proc_dict[proc['pid']]={'file':proc['file'],'yara':proc['yara']}
            for pid in proc_dict.keys():
                image = ImageInfo()
                image.path = proc_dict[pid][file]
                image.current_directory = os.path.dirname(proc_dict[pid][file])
                image.file_name = os.path.basename(proc_dict[pid][file])
                if pid==root_process.pid:
                    root_process.image_info=image
                else:
                    try:
                        embedded_process = root_process.find_embedded_process(pid)
                        embedded_process.image_info = image
                    except Exception, e:
                        pass
        return root_process


    def bind_static(self):
        static = self.analysis_handler.static.dictionary
        static_object = CyboxObject(objecttype=WinExecutableFile).objecttype
        self.static_bundle = MaecBundle()
        self.analysis_static =MaecAnalysis(namespace=self.namespace)
        self.analysis_static.add_method('static')
        self.analysis_static.add_type('triage')
        self.analysis_static.add_ordinal_position(2)
        self.analysis_static.addsource(method='IoCs Generator System',name='George Sakellariou',organization='UOM')
        self.analysis_static.addsummary('Results of static section')
        pe_exports = static['pe_exports']
        exports = PEExports()
        if pe_exports:
            exported_functions=PEExportedFunctions()
            exports.number_of_functions= len(pe_exports)
            exports.exports_time_stamp = static['pe_timestamp']
            count_names=[]
            count_addr =[]
            while pe_exports:
                function=PEExportedFunction()
                pe_func_data=pe_exports.pop()
                function.entry_point=pe_func_data['address']
                if not pe_func_data['address'] in count_addr:
                    count_addr.append(pe_func_data['address'])
                function.ordinal=pe_func_data['ordinal']
                function.function_name=pe_func_data['name']
                if not pe_func_data['name'] in count_names:
                    count_names.append(pe_func_data['name'])
                exported_functions.append(function)
            exports.exported_functions=exported_functions
            exports.number_of_addresses=len(count_addr)
            exports.number_of_names=len(count_names)
        pe_imports=static['pe_imports']
        imports= PEImportList()
        if pe_imports:
            for imported_pe in pe_imports:
                imported_functions = imported_pe['imports']
                imported_func_list= PEImportedFunctions()
                ordinal =0
                for function in imported_functions:
                    ordinal+=1
                    func_obj = PEImportedFunction()
                    func_obj.function_name=function['name']
                    func_obj.virtual_address = function['address']
                    func_obj.ordinal = ordinal
                    imported_func_list.append(func_obj)
                import_file = PEImport()
                import_file.file_name=imported_pe['dll']
                import_file.imported_functions=imported_func_list
                imports.append(import_file)
        pe_sections=static['pe_sections']
        sections = PESectionList()
        if pe_sections:
            for section in pe_sections:
                pe_section= PESection()
                header = PESectionHeaderStruct()
                header.name=section['name']
                header.virtual_address=section['virtual_address']
                header.virtual_size=section['virtual_size']
                header.size_of_raw_data=section['size_of_data']
                pe_section.section_header=header
                entropy = Entropy()
                entropy.value=section['entropy']
                pe_section.entropy=entropy
                sections.append(pe_section)
        pe_resources= static['pe_resources']
        resources = PEResourceList()
        if pe_resources:
            for pe_resource in pe_resources:
                resource = PEResource()
                resource.language= pe_resource['language']
                resource.sub_language = pe_resource['sublanguage']
                resource.type_ = pe_resource['filetype']
                resource.size= pe_resource['size']
                resource.name=pe_resource['name']
                resource.data = pe_resource['offset']
                resources.append(resource)
        pe_versioninfo= static['pe_versioninfo']
        if pe_versioninfo:
            version_info = PEVersionInfoResource()
            for entry in pe_versioninfo:
                if entry['name']=='LegalCopyright':
                    version_info.legalcopyright=entry['value']
                elif entry['name'] =='FileVersion':
                    version_info.fileversion=entry['value']
                elif entry['name'] == 'CompanyName':
                    version_info.companyname = entry['value']
                elif entry['name']=='Comments':
                    version_info.comments = entry['value']
                elif entry['name']=='ProductName':
                    version_info.productname = entry['value']
                elif entry['name']=='ProductVersion':
                    version_info.productversion=entry['value']
                elif entry['name']=='FileDescription':
                    version_info.filedescription = entry['value']
                elif entry['name']=='Translation':
                    version_info.internalname = entry['value']
                elif entry['name']=='LangID':
                    version_info.langid = entry['value']
                elif entry['name']=='LegalTrademarks':
                    version_info.legaltrademarks= entry['value']
                elif entry['name']=='SpecialBuild':
                    version_info.specialbuild= entry['value']
                elif entry['name']=='PrivateBuild':
                    version_info.privatebuild= entry['value']
                elif entry['name']=='OriginalFilename':
                    version_info.originalfilename = entry['value']
            resources.append(version_info)
        headers = PEHeaders()
        headers.signature=static['peid_signatures']
        file_header =PEFileHeader()
        file_header.time_date_stamp=static['pe_timestamp']
        file_header.number_of_sections=len(pe_sections)
        imphash = Hash(hash_value=static['pe_imphash'],type_=Hash.TYPE_MD5)
        file_header.hashes = HashList()
        file_header.hashes.append(imphash)
        headers.file_header=file_header
        static_object.headers = headers
        static_object.resources = resources
        static_object.sections=sections
        static_object.exports = exports
        static_object.imports = imports
        extracted_feautures= ExtractedFeatures()
        extracted_feautures.strings=self.bind_strings()
        static_object.extracted_features = extracted_feautures
        self.static_bundle.add_object(static_object)

    def bind_dropped(self):
        dropped_list = self.analysis_handler.dropped.list
        if dropped_list:
            for dropped in dropped_list:
                objectype = CyboxObject().objecttype
                objectype.size=dropped['size']
                objectype.add_hash(Hash(hash_value=dropped['sha1'],type_=Hash.TYPE_SHA1))
                objectype.add_hash(Hash(hash_value=dropped['md5'],type_=Hash.TYPE_MD5))
                objectype.add_hash(Hash(hash_value=dropped['sha256'],type_=Hash.TYPE_SHA256))
                objectype.add_hash(Hash(hash_value=dropped['sha512'],type_=Hash.TYPE_SHA512))
                objectype.add_hash(Hash(hash_value=dropped['crc32'],type_=Hash.TYPE_OTHER))
                objectype.add_hash(Hash(hash_value=dropped['ssdeep'],type_=Hash.TYPE_SSDEEP))
                objectype.file_name=dropped['name']
                objectype.device_path = os.path.dirname(dropped['path'])
                objectype.full_path = dropped['path']
                objectype.size_in_bytes = dropped['size']
                objectype.file_extension = '.'.join(dropped['name'].split('.')[1:])
                objectype.file_format = dropped['type']
                self.bundle.objects.append(objectype)

    def bind_behavior(self):
        behavior = self.analysis_handler.behavior.dictionary
        processtree=behavior['processtree']
        process_tree = process_tree_from_list(processtree)
        processes= behavior['processes']
        root_process = process_tree.root_process
        for process in processes:
            if process['process_id']==root_process.pid:
                root_process.start_time=DateTime(value=datetime.datetime.strptime(process['first_seen'],"%Y-%m-%d %H:%M:%S,%f"))
                calls = process['calls']
                associated_objects={}
                for call in calls:
                    action=MaecBundleAction()
                    parameters = []
                    arg_count=0
                    for argument in call['arguments']:
                        arg_count+=1
                        parameters.append(action.create_action_implementation_api_call_parameter(ordinal_position=arg_count,name=argument['name'],value='value'))
                    api_call = action.create_action_implementation_api_call(function_name=call['api'],
                                                                            parameters=parameters,return_value=call['return'])
                    action.add_timestamp(call['timestamp'])
                    action.add_frequnecy(call['repeated'])
                    action.add_action_implementation_api_call(api_call)
                    if call['thread_id'] in associated_objects.keys():
                        action.add_associated_objects(associated_objects[call['thread_id']])
                    else:
                        ass_obj = action.create_associated_object(defined_object=WinThread())
                        ass_obj.properties.thread_id=call['thread_id']
                        associated_objects[call['thread_id']]=ass_obj
                        action.add_associated_objects(ass_obj)
                    root_process.add_initiated_action(action_id=action.id_)
                    self.bundle.add_action(action)
            else:
                embedded_process = root_process.find_embedded_process(process['process_id'])
                embedded_process.start_time=DateTime(value=datetime.datetime.strptime(process['first_seen'],"%Y-%m-%d %H:%M:%S,%f"))
                calls = process['calls']
                associated_objects={}
                for call in calls:
                    action=MaecBundleAction()
                    parameters = []
                    arg_count=0
                    for argument in call['arguments']:
                        arg_count+=1
                        parameters.append(action.create_action_implementation_api_call_parameter(ordinal_position=arg_count,name=argument['name'],value='value'))
                    api_call = action.create_action_implementation_api_call(function_name=call['api'],
                                                                            parameters=parameters,return_value=call['return'])
                    action.add_timestamp(call['timestamp'])
                    action.add_frequnecy(call['repeated'])
                    action.add_action_implementation_api_call(api_call)
                    if call['thread_id'] in associated_objects.keys():
                        action.add_associated_objects(associated_objects[call['thread_id']])
                    else:
                        ass_obj = action.create_associated_object(defined_object=WinThread())
                        ass_obj.properties.thread_id=call['thread_id']
                        associated_objects[call['thread_id']]=ass_obj
                        action.add_associated_objects(ass_obj)
                    embedded_process.add_initiated_action(action_id=action.id_)
                    self.bundle.add_action(action)

        process_tree.set_root_process(self.bind_procmemory(root_process))
        self.bundle.process_tree=process_tree

    def bind_strings(self):
        strings = self.analysis_handler.strings.list
        extracted_strings=None
        if strings:
            extracted_strings = ExtractedStrings()
            for string in strings:
                string_obj= ExtractedString()
                hash_list= HashList()
                string_obj.string_value=string
                string_obj.byte_string_value="".join("{:02x}".format(ord(c)) for c in string)
                string_md5_value= hashlib.md5(string).hexdigest()
                string_sha1_value = hashlib.sha1(string).hexdigest()
                md5_obj=Hash(hash_value=string_md5_value,type_=Hash.TYPE_MD5)
                hash_list.append(md5_obj)
                sha1_obj = Hash(hash_value=string_sha1_value,type_=Hash.TYPE_SHA1)
                hash_list.append(sha1_obj)
                string_obj.hashes=hash_list
                string_obj.length=len(string)
                #Activation after better detect implementation
                '''
                try:
                    string_obj.language = detect(string)
                except Exception,e:
                    string_obj.language=None
                '''
                extracted_strings.append(string_obj)
        return extracted_strings

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
        self.bundle.objects = ObjectList()
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
        self.analysis.set_findings_bundle(self.bundle.id_)
        self.analysis_static.set_findings_bundle(self.static_bundle.id_)
        self.subject.add_analysis(self.analysis)
        self.subject.add_analysis(self.analysis_static)
        self.subject.addbundleinfindingbundles(self.bundle)
        self.subject.addbundleinfindingbundles(self.static_bundle)


def process_tree_from_list(tree_list):
    p_tree = ProcessTree()
    root = ProcessTreeNode()
    process = tree_list.pop()
    root.pid = process['pid']
    root.name=process['name']
    root.parent_pid = process['parent_id']
    children=process['children']
    if children:
        children_pid_list=ChildPIDList()
        for child in children:
            children_pid_list.append(child['pid'])
        root.child_pid_list=children_pid_list
        complete_processes_list=children_list_recovery(children)
        tree_pid=[]
        tree_pid.append(root.pid)
        while complete_processes_list:
            for proc in complete_processes_list:
                if proc['parent_id'] in tree_pid:
                    process_node = ProcessTreeNode()
                    process_node.parent_pid=proc['parent_id']
                    process_node.pid=proc['pid']
                    process_node.name=proc['name']
                    child_list_helper = ChildPIDList()
                    for cpid in proc['child_pid_list']:
                        child_list_helper.append(cpid)
                    process_node.child_pid_list=child_list_helper
                    root.add_spawned_process(process_node,str(proc['parent_id']))
                    tree_pid.append(proc['pid'])
                    complete_processes_list.remove(proc)
    p_tree.set_root_process(root)
    return p_tree



def children_list_recovery(children,list_children=None):
    if not children:
        return list_children
    elif children and (list_children is None):
        list_children=[]
        for child in children:
            children_of_child = child.pop('children')
            child['child_pid_list']= [c['pid'] for c in children_of_child]
            list_children.append(child)
            list_children = children_list_recovery(children_of_child,list_children)
        return list_children
    elif children and (list_children is not None):
        for child in children:
            children_of_child = child.pop('children')
            child['child_pid_list']= [c['pid'] for c in children_of_child]
            list_children.append(child)
            list_children = children_list_recovery(children_of_child,list_children)
        return list_children

if __name__=='__main__':
    results = load_results('cuckoo_results')
    # Testing
    mc = MAECMalwareSubjectCreator(results)
    report=mc.return_malware_subject()
    print(report)
    import os
    filexml=open('resultxml.txt','w')
    filexml.write(report)
    filexml.close()

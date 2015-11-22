'''
@author: george
Initalize the configuration files adding system variables
'''
import os, ConfigParser,uuid,argparse,subprocess

DEFAULT_ANALYSIS_PATH= os.path.abspath(os.path.join(os.path.dirname(__file__),"analysis_hub"))
DEFAULT_SERVER_CERTIFICATE_PATH=os.path.abspath(os.path.join(os.path.dirname(__file__),"server/server_certificate"))
DEFAULT_MALWARE_SAMPLES_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__),"malware_hub"))

DEFAULT_SERVER_HOST = 'localhost'
DEFAULT_SERVER_PORT = 10000
DEFAULT_INIT_SERVER_PORT = 8000


def main():
    parser = argparse.ArgumentParser(description='This program configure ioc server')
    parser.add_argument('-apath',action='store',dest='apath', help='Path of analysis directory. Here are stored results coming from analyzers')
    parser.add_argument('-mpath',action='store',dest='mpath', help='Path of malware samples directory. Here are stored malware subjects coming for analysis')
    parser.add_argument('-host',action='store',dest='host',help='Host address of IoC server')
    parser.add_argument('-port',action='store',dest='port',help='IoC server port')
    parser.add_argument('-iport',action='store',dest='iport',help='Init server port')

    args = parser.parse_args()

    try:
        print('Creating configuration directory.')
        subprocess.call(['mkdir','conf'])
        print('Creating log directory.')
        subprocess.call(['mkdir','log'])
        print('Creating malware samples hub')
        subprocess.call(['mkdir','malware_hub'])
        print('Creating analysis directory')
        subprocess.call(['mkdir','malware_hub'])
    except Exception, e:
        print e

    if args.apath is not None:
        ANALYSIS_PATH = args.apath
    else:
        ANALYSIS_PATH = DEFAULT_ANALYSIS_PATH
    print "Analysis path is initialized to : %s"%ANALYSIS_PATH

    if args.mpath is not None:
        MALWARE_PATH = args.mpath
    else:
        MALWARE_PATH = DEFAULT_MALWARE_SAMPLES_PATH
    print "Malware samples path is initialized to : %s"%MALWARE_PATH

    if args.host is not None:
        SERVER_HOST = args.host
    else:
        SERVER_HOST = DEFAULT_SERVER_HOST
    print "Server host is initialized to : %s"%SERVER_HOST

    INIT_SERVER_HOST = SERVER_HOST

    if args.port is not None:
        SERVER_PORT = args.port
    else:
        SERVER_PORT = DEFAULT_SERVER_PORT
    print "Server port is initialized to : %s"%SERVER_PORT

    if args.iport is not None:
        INIT_SERVER_PORT = args.iport
    else:
        INIT_SERVER_PORT = DEFAULT_INIT_SERVER_PORT
    print "Init server port is initialized to : %s"%INIT_SERVER_PORT

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
        print('Initialize configuration file of Server')
        config.add_section('Server')
        config.set('Server', 'ANALYSIS_PATH',ANALYSIS_PATH)
        config.set('Server','MALWARE_PATH',MALWARE_PATH)
        config.set('Server', 'FILENUMBER', '0')
        config.set('Server', 'DBFILENAME', 'cuckoo_results_')
        config.set('Server', 'ADDRESS', SERVER_HOST)
        config.set('Server', 'PORT', SERVER_PORT)
        config.set('Server', 'INIT_ADDRESS', INIT_SERVER_HOST)
        config.set('Server', 'INIT_PORT', INIT_SERVER_PORT)
        config.set('Server', 'SERVER_CERTIFICATE', DEFAULT_SERVER_CERTIFICATE_PATH)

        config.set('Server','SERVER_ID',uuid.uuid1())
        # Writing configuration file to 'server.conf'
        print("Writing configuration file to 'server.conf'")
        with open(os.path.abspath(os.path.join(os.path.dirname(__file__),'conf','server.conf')), 'w') as configfile:
            config.write(configfile)
            configfile.close()
        config.remove_section('Server')
        #Initialize configuration file of MAEC
        print('Initialize configuration file of MAEC')
        config.add_section('maec')
        config.set('maec', 'MAEC_PATH', os.path.abspath(os.path.join(os.path.dirname(__file__),"maec_results")))
        config.set('maec', 'MAEC_PATH_BUNDLES', os.path.abspath(os.path.join(os.path.dirname(__file__),"maec_results","bundles")))
        config.set('maec', 'MAEC_PATH_PACKAGES', os.path.abspath(os.path.join(os.path.dirname(__file__),"maec_results","packages")))
        config.set('maec', 'MAEC_PATH_CONTAINERS', os.path.abspath(os.path.join(os.path.dirname(__file__),"maec_results","containers")))
        config.add_section('xml_schema')
        config.set('xml_schema', 'XML_PATH', os.path.abspath(os.path.join(os.path.dirname(__file__),"xml_schemas")))
        config.set('xml_schema', 'CYBOX_DV_SCHEMA_PATH', os.path.abspath(os.path.join(os.path.dirname(__file__),"xml_schemas","cybox_default_vocabularies.xsd")))
        config.set('xml_schema', 'BUNDLE_SCHEMA_PATH', os.path.abspath(os.path.join(os.path.dirname(__file__),"xml_schemas","maec_bundle_schema.xsd")))
        config.set('xml_schema', 'CONTAINER_SCHEMA_PATH', os.path.abspath(os.path.join(os.path.dirname(__file__),"xml_schemas","maec_container_schema.xsd")))
        config.set('xml_schema', 'PACKAGE_SCHEMA_PATH', os.path.abspath(os.path.join(os.path.dirname(__file__),"xml_schemas","maec_package_schema.xsd")))
        config.set('xml_schema', 'MAEC_DV_SCHEMA_PATH', os.path.abspath(os.path.join(os.path.dirname(__file__),"xml_schemas","maec_default_vocabularies.xsd")))
        # Writing configuration file to 'maec.conf'
        print("Writing configuration file to 'maec.conf'")
        with open(os.path.abspath(os.path.join(os.path.dirname(__file__),'conf','maec.conf')), 'w') as configfile:
            config.write(configfile)
            configfile.close()
        config.remove_section('maec')
        config.remove_section('xml_schema')

        #Initialize configuration file of Cuckoo Results
        print('Initialize configuration file of Cuckoo Results')
        config.add_section('analysisinfo')
        config.set('analysisinfo','description','analysisinfo describes the structure of the analysis info dictionary of  Cuckoo Results.')
        config.set('analysisinfo','key','info')
        config.set('analysisinfo','keys','version,started,ended,duration,id,category,custom,package,machine')
        config.set('analysisinfo','encapsulation',True)
        config.set('analysisinfo','subsections','machine')

        config.add_section('subsection_machine')
        config.set('subsection_machine','key','machine')
        config.set('subsection_machine','encapsulation',False)
        config.set('subsection_machine','keys','id,name,label,manager,started_on,shutdown_on')

        config.add_section('procmemory')
        config.set('procmemory','description','procmemory describes the structure of the elements that they can be appended in procmemory list of Cuckoo Results.')
        config.set('procmemory','key','procmemory')
        config.set('procmemory','encapsulation',True)
        config.set('procmemory','keys','file,pid,yara')
        config.set('procmemory','subsections','yara')

        config.add_section('subsection_yara')
        config.set('subsection_yara','key','yara')
        config.set('subsection_yara','encapsulation',False)
        config.set('subsection_yara','keys','name,meta,strings')

        config.add_section('static')
        config.set('static','description','static describes the structure of the static dictionary of Cuckoo Results.')
        config.set('static','key','static')
        config.set('static','keys','peid_signatures,pe_imports,pe_exports,pe_sections,pe_resources,pe_versioninfo,pe_imphash,pe_timestamp,imported_dll_count')
        config.set('static','encapsulation',True)
        config.set('static','subsections','pe_imports,pe_exports,pe_sections,pe_resources,pe_versioninfo')

        config.add_section('subsection_pe_imports')
        config.set('subsection_pe_imports','key','pe_imports')
        config.set('subsection_pe_imports','keys','imports,dll')
        config.set('subsection_pe_imports','encapsulation',True)
        config.set('subsection_pe_imports','subsections','imports')

        config.add_section('subsection_imports')
        config.set('subsection_imports','key','imports')
        config.set('subsection_imports','keys','address,name')
        config.set('subsection_imports','encapsulation',False)

        config.add_section('subsection_pe_exports')
        config.set('subsection_pe_exports','key','pe_exports')
        config.set('subsection_pe_exports','keys','address,name,ordinal')
        config.set('subsection_pe_exports','encapsulation',False)

        config.add_section('subsection_pe_sections')
        config.set('subsection_pe_sections','key','pe_sections')
        config.set('subsection_pe_sections','keys','name,virtual_address,virtual_size,size_of_data,entropy')
        config.set('subsection_pe_sections','encapsulation',False)

        config.add_section('subsection_pe_resources')
        config.set('subsection_pe_resources','key','pe_resources')
        config.set('subsection_pe_resources','keys','name,offset,size,filetype,language,sublanguage')
        config.set('subsection_pe_resources','encapsulation',False)

        config.add_section('subsection_pe_versioninfo')
        config.set('subsection_pe_versioninfo','key','pe_versioninfo')
        config.set('subsection_pe_versioninfo','keys','name,value')
        config.set('subsection_pe_versioninfo','encapsulation',False)

        config.add_section('dropped')
        config.set('dropped','description','dropped describes the structure of the elements that they can be appended in dropped list of Cuckoo Results.')
        config.set('dropped','key','dropped')
        config.set('dropped','keys','name,path,size,crc32,md5,sha1,sha256,sha512,ssdeep,type,yara')
        config.set('dropped','encapsulation',True)
        config.set('dropped','subsections','yara')

        config.add_section('behavior')
        config.set('behavior','description','behavior describes the structure of the behavior dictionary of Cuckoo Results.')
        config.set('behavior','key','behavior')
        config.set('behavior','keys','processes,processtree,anomaly,enhanced,summary')
        config.set('behavior','encapsulation',True)
        config.set('behavior','subsections','processes,processtree,anomaly,enhanced,summary')

        config.add_section('subsection_processes')
        config.set('subsection_processes','key','processes')
        config.set('subsection_processes','keys','process_id,process_name,parent_id,first_seen,calls')
        config.set('subsection_processes','encapsulation',True)
        config.set('subsection_processes','subsections','calls')

        config.add_section('subsection_calls')
        config.set('subsection_calls','key','calls')
        config.set('subsection_calls','keys','timestamp,thread_id,category,api,status,return,repeated,arguments')
        config.set('subsection_calls','encapsulation',True)
        config.set('subsection_calls','subsections','arguments')

        config.add_section('subsection_arguments')
        config.set('subsection_arguments','key','arguments')
        config.set('subsection_arguments','keys','name,value')
        config.set('subsection_arguments','encapsulation',False)

        config.add_section('subsection_processtree')
        config.set('subsection_processtree','key','processtree')
        config.set('subsection_processtree','keys','name,pid,parent_id,children')
        config.set('subsection_processtree','encapsulation',False)

        config.add_section('subsection_anomaly')
        config.set('subsection_anomaly','key','anomaly')
        config.set('subsection_anomaly','keys','name,pid,category,funcname,message')
        config.set('subsection_anomaly','encapsulation',False)

        config.add_section('subsection_enhanced')
        config.set('subsection_enhanced','key','enhanced')
        config.set('subsection_enhanced','keys','event,object,timestamp,eid,data')
        config.set('subsection_enhanced','encapsulation',True)
        config.set('subsection_enhanced','subsections','data')

        config.add_section('subsection_data')
        config.set('subsection_data','key','data')
        config.set('subsection_data','keys','from,to,file,pathtofile,moduleaddress,classname,windowname,content,object,regkey,controlcode,service,action,id,procedureaddress,module')
        config.set('subsection_data','encapsulation',False)

        config.add_section('subsection_summary')
        config.set('subsection_summary','key','summary')
        config.set('subsection_summary','keys','files,keys,mutexes')
        config.set('subsection_summary','encapsulation',False)

        config.add_section('strings')
        config.set('strings','description','strings describes the structure of the strings list of Cuckoo Results.')
        config.set('strings','key','strings')
        config.set('strings','keys','')
        config.set('strings','encapsulation',False)

        config.add_section('debug')
        config.set('debug','description','debug describes the structure of the debug dictionary of Cuckoo Results.')
        config.set('debug','key','debug')
        config.set('debug','keys','log,errors')
        config.set('debug','encapsulation',False)

        config.add_section('memory')
        config.set('memory','description','memory describes the structure of the memory dictionary of Cuckoo Results.')
        config.set('memory','key','memory')
        config.set('memory','keys','pslist,psxview,callback,idt,ssdt,gdt,timers,messagehooks,getsids,privs,malfind,apihooks,dlllist,handles,ldrmodules,mutantscan,devicetree,svcscan,modscan,yarascan')
        config.set('memory','encapsulation',True)
        config.set('memory','subsections','pslist,psxview,callbacks,idt,ssdt,gdt,timers,messagehooks,getsids,privs,malfind,apihooks,dlllist,handles,ldrmodules,mutantscan,devicetree,svcscan,modscan,yarascan')

        config.add_section('subsection_pslist')
        config.set('subsection_pslist','key','pslist')
        config.set('subsection_pslist','keys','config,data')
        config.set('subsection_pslist','encapsulation',True)
        config.set('subsection_pslist','subsections','pslist_data')

        config.add_section('subsection_pslist_data')
        config.set('subsection_pslist_data','key','pslist_data')
        config.set('subsection_pslist_data','keys','process_name,process_id,parent_id,num_threads,num_handles,session_id,create_time,exit_time')
        config.set('subsection_pslist_data','encapsulation',False)

        config.add_section('subsection_psxview')
        config.set('subsection_psxview','key','psxview')
        config.set('subsection_psxview','keys','config,data')
        config.set('subsection_psxview','encapsulation',True)
        config.set('subsection_psxview','subsections','psxview_data')

        config.add_section('subsection_psxview_data')
        config.set('subsection_psxview_data','key','psxview_data')
        config.set('subsection_psxview_data','keys','process_name,process_id,pslist,psscan,thrdproc,pspcid,csrss,session,deskthrd')
        config.set('subsection_psxview_data','encapsulation',False)

        config.add_section('subsection_callbacks')
        config.set('subsection_callbacks','key','callbacks')
        config.set('subsection_callbacks','keys','config,data')
        config.set('subsection_callbacks','encapsulation',True)
        config.set('subsection_callbacks','subsections','callbacks_data')

        config.add_section('subsection_callbacks_data')
        config.set('subsection_callbacks_data','key','callbacks_data')
        config.set('subsection_callbacks_data','keys','type,callback,module,details')
        config.set('subsection_callbacks_data','encapsulation',False)

        config.add_section('subsection_idt')
        config.set('subsection_idt','key','idt')
        config.set('subsection_idt','keys','config,data')
        config.set('subsection_idt','encapsulation',True)
        config.set('subsection_idt','subsections','idt_data')

        config.add_section('subsection_idt_data')
        config.set('subsection_idt_data','key','idt_data')
        config.set('subsection_idt_data','keys','cpu_number,index,selector,address,module,section')
        config.set('subsection_idt_data','encapsulation',False)

        config.add_section('subsection_ssdt')
        config.set('subsection_ssdt','key','ssdt')
        config.set('subsection_ssdt','keys','config,data')
        config.set('subsection_ssdt','encapsulation',True)
        config.set('subsection_ssdt','subsections','ssdt_data')

        config.add_section('subsection_ssdt_data')
        config.set('subsection_ssdt_data','key','ssdt_data')
        config.set('subsection_ssdt_data','keys','index,table,entry,syscall_name,syscall_addr,syscall_modname,hook_dest_addr,hook_name')
        config.set('subsection_ssdt_data','encapsulation',False)

        config.add_section('subsection_gdt')
        config.set('subsection_gdt','key','gdt')
        config.set('subsection_gdt','keys','config,data')
        config.set('subsection_gdt','encapsulation',True)
        config.set('subsection_gdt','subsections','gdt_data')

        config.add_section('subsection_gdt_data')
        config.set('subsection_gdt_data','key','gdt_data')
        config.set('subsection_gdt_data','keys','cpu_number,selector,base,limit,type,dpl,granularity,present')
        config.set('subsection_gdt_data','encapsulation',False)

        config.add_section('subsection_timers')
        config.set('subsection_timers','key','timers')
        config.set('subsection_timers','keys','config,data')
        config.set('subsection_timers','encapsulation',True)
        config.set('subsection_timers','subsections','timers_data')

        config.add_section('subsection_timers_data')
        config.set('subsection_timers_data','key','timers_data')
        config.set('subsection_timers_data','keys','offset,due_time,period,signaled,routine,module')
        config.set('subsection_timers_data','encapsulation',False)

        config.add_section('subsection_messagehooks')
        config.set('subsection_messagehooks','key','messagehooks')
        config.set('subsection_messagehooks','keys','config,data')
        config.set('subsection_messagehooks','encapsulation',True)
        config.set('subsection_messagehooks','subsections','messagehooks_data')

        config.add_section('subsection_messagehooks_data')
        config.set('subsection_messagehooks_data','key','messagehooks_data')
        config.set('subsection_messagehooks_data','keys','offset,session,desktop,thread,filter,flags,function,module')
        config.set('subsection_messagehooks_data','encapsulation',False)

        config.add_section('subsection_getsids')
        config.set('subsection_getsids','key','getsids')
        config.set('subsection_getsids','keys','config,data')
        config.set('subsection_getsids','encapsulation',True)
        config.set('subsection_getsids','subsections','getsids_data')

        config.add_section('subsection_getsids_data')
        config.set('subsection_getsids_data','key','getsids_data')
        config.set('subsection_getsids_data','keys','filename,process_id,sid_string,sid_name')
        config.set('subsection_getsids_data','encapsulation',False)

        config.add_section('subsection_privs')
        config.set('subsection_privs','key','privs')
        config.set('subsection_privs','keys','config,data')
        config.set('subsection_privs','encapsulation',True)
        config.set('subsection_privs','subsections','privs_data')

        config.add_section('subsection_privs_data')
        config.set('subsection_privs_data','key','privs_data')
        config.set('subsection_privs_data','keys','process_id,filename,value,privilege,attributes,description')
        config.set('subsection_privs_data','encapsulation',False)

        config.add_section('subsection_malfind')
        config.set('subsection_malfind','key','malfind')
        config.set('subsection_malfind','keys','config,data')
        config.set('subsection_malfind','encapsulation',True)
        config.set('subsection_malfind','subsections','malfind_data')

        config.add_section('subsection_malfind_data')
        config.set('subsection_malfind_data','key','malfind_data')
        config.set('subsection_malfind_data','keys','process_name,process_id,vad_start,vad_tag')
        config.set('subsection_malfind_data','encapsulation',False)

        config.add_section('subsection_yarascan')
        config.set('subsection_yarascan','key','yarascan')
        config.set('subsection_yarascan','keys','config,data')
        config.set('subsection_yarascan','encapsulation',True)
        config.set('subsection_yarascan','subsections','yarascan_data')

        config.add_section('subsection_yarascan_data')
        config.set('subsection_yarascan_data','key','yarascan_data')
        config.set('subsection_yarascan_data','keys','rule,owner,hedump')
        config.set('subsection_yarascan_data','encapsulation',False)

        config.add_section('subsection_apihooks')
        config.set('subsection_apihooks','key','apihooks')
        config.set('subsection_apihooks','keys','config,data')
        config.set('subsection_apihooks','encapsulation',True)
        config.set('subsection_apihooks','subsections','apihooks_data')

        config.add_section('subsection_apihooks_data')
        config.set('subsection_apihooks_data','key','apihooks_data')
        config.set('subsection_apihooks_data','keys','process_id,process_name,hook_mode,hook_type,victim_module,victim_function,hook_address,hooking_module')
        config.set('subsection_apihooks_data','encapsulation',False)

        config.add_section('subsection_handles')
        config.set('subsection_handles','key','handles')
        config.set('subsection_handles','keys','config,data')
        config.set('subsection_handles','encapsulation',True)
        config.set('subsection_handles','subsections','handles_data')

        config.add_section('subsection_handles_data')
        config.set('subsection_handles_data','key','handles_data')
        config.set('subsection_handles_data','keys','process_id,handle_value,handle_granted_access,handle_type,handle_name')
        config.set('subsection_handles_data','encapsulation',False)

        config.add_section('subsection_dlllist')
        config.set('subsection_dlllist','key','dlllist')
        config.set('subsection_dlllist','keys','config,data')
        config.set('subsection_dlllist','encapsulation',True)
        config.set('subsection_dlllist','subsections','dlllist_data')

        config.add_section('subsection_dlllist_data')
        config.set('subsection_dlllist_data','key','dlllist_data')
        config.set('subsection_dlllist_data','keys','process_id,process_name,commandline,loaded_modules')
        config.set('subsection_dlllist_data','encapsulation',True)
        config.set('subsection_dlllist_data','subsections','loaded_modules')

        config.add_section('subsection_loaded_modules')
        config.set('subsection_loaded_modules','key','loaded_modules')
        config.set('subsection_loaded_modules','keys','dll_base,dll_size,dll_full_name,dll_load_count')
        config.set('subsection_loaded_modules','encapsulation',False)

        config.add_section('subsection_ldrmodules')
        config.set('subsection_ldrmodules','key','ldrmodules')
        config.set('subsection_ldrmodules','keys','config,data')
        config.set('subsection_ldrmodules','encapsulation',True)
        config.set('subsection_ldrmodules','subsections','ldrmodules_data')

        config.add_section('subsection_ldrmodules_data')
        config.set('subsection_ldrmodules_data','key','ldrmodules_data')
        config.set('subsection_ldrmodules_data','keys','process_id,process_name,dll_base,dll_in_load,dll_in_int,dll_in_mem,dll_mapped_path,load_full_dll_name,init_full_dll_name,mem_full_dll_name')
        config.set('subsection_ldrmodules_data','encapsulation',False)

        config.add_section('subsection_mutantscan')
        config.set('subsection_mutantscan','key','mutantscan')
        config.set('subsection_mutantscan','keys','config,data')
        config.set('subsection_mutantscan','encapsulation',True)
        config.set('subsection_mutantscan','subsections','mutantscan_data')

        config.add_section('subsection_mutantscan_data')
        config.set('subsection_mutantscan_data','key','mutantscan_data')
        config.set('subsection_mutantscan_data','keys','mutant_offset,num_pointer,num_handles,mutant_signal_state,mutant_name,process_id,thread_id')
        config.set('subsection_mutantscan_data','encapsulation',False)

        config.add_section('subsection_devicetree')
        config.set('subsection_devicetree','key','devicetree')
        config.set('subsection_devicetree','keys','config,data')
        config.set('subsection_devicetree','encapsulation',True)
        config.set('subsection_devicetree','subsections','devicetree_data')

        config.add_section('subsection_devicetree_data')
        config.set('subsection_devicetree_data','key','devicetree_data')
        config.set('subsection_devicetree_data','keys','driver_offset,driver_name,devices')
        config.set('subsection_devicetree_data','encapsulation',True)
        config.set('subsection_devicetree_data','subsections','devices')

        config.add_section('subsection_devices')
        config.set('subsection_devices','key','devices')
        config.set('subsection_devices','keys','device_offset,device_name,device_type,devices_attached')
        config.set('subsection_devices','encapsulation',True)
        config.set('subsection_devices','subsections','devices_attached')

        config.add_section('subsection_devices_attached')
        config.set('subsection_devices_attached','key','devices_attached')
        config.set('subsection_devices_attached','keys','level,attached_device_offset,attached_device_name,attached_device_type')
        config.set('subsection_devices_attached','encapsulation',False)

        config.add_section('subsection_svcscan')
        config.set('subsection_svcscan','key','svcscan')
        config.set('subsection_svcscan','keys','config,data')
        config.set('subsection_svcscan','encapsulation',True)
        config.set('subsection_svcscan','subsections','svcscan_data')

        config.add_section('subsection_svcscan_data')
        config.set('subsection_svcscan_data','key','svcscan_data')
        config.set('subsection_svcscan_data','keys','service_offset,service_order,process_id,service_name,service_display_name,service_type,service_binary_path,service_state')
        config.set('subsection_svcscan_data','encapsulation',False)

        config.add_section('subsection_modscan')
        config.set('subsection_modscan','key','modscan')
        config.set('subsection_modscan','keys','config,data')
        config.set('subsection_modscan','encapsulation',True)
        config.set('subsection_modscan','subsections','modscan_data')

        config.add_section('subsection_modscan_data')
        config.set('subsection_modscan_data','key','modscan_data')
        config.set('subsection_modscan_data','keys','kernel_module_offset,kernel_module_name,kernel_module_file,kernel_module_base,kernel_module_size')
        config.set('subsection_modscan_data','encapsulation',False)

        config.add_section('targetinfo')
        config.set('targetinfo','description','targetinfo describes the structure of the targetinfo dictionary of Cuckoo Results.')
        config.set('targetinfo','key','target')
        config.set('targetinfo','keys','category,file,url')
        config.set('targetinfo','encapsulation',True)
        config.set('targetinfo','subsections','file')

        config.add_section('subsection_file')
        config.set('subsection_file','key','file')
        config.set('subsection_file','keys','name,path,size,crc32,md5,sha1,sha256,sha512,ssdeep,type,yara')
        config.set('subsection_file','encapsulation',True)
        config.set('subsection_file','subsections','yara')

        config.add_section('virustotal')
        config.set('virustotal','description','virustotal describes the structure of the virustotal dictionary of Cuckoo Results.')
        config.set('virustotal','key','virustotal')
        config.set('virustotal','keys','scans')
        config.set('virustotal','encapsulation',True)
        config.set('virustotal','subsections','scans')

        config.add_section('subsection_scans')
        config.set('subsection_scans','key','engine')
        config.set('subsection_scans','keys','detected,version,result,update')
        config.set('subsection_scans','encapsulation',False)


        config.add_section('network')
        config.set('network','description','network describes the structure of the network dictionary of Cuckoo Results.')
        config.set('network','key','network')
        config.set('network','keys','pcap_sha256,sorted_pcap_sha256,hosts,domains,tcp,udp,icmp,http,dns,smtp,irc')
        config.set('network','encapsulation',True)
        config.set('network','subsections','domains,tcp,udp,icmp,http,dns,smtp')

        config.add_section('subsection_tcp')
        config.set('subsection_tcp','key','tcp')
        config.set('subsection_tcp','keys','src,dst,offset,sport,dport,time')
        config.set('subsection_tcp','encapsulation',False)

        config.add_section('subsection_http')
        config.set('subsection_http','key','http')
        config.set('subsection_http','keys','count,host,port,data,uri,body,path,user_agent,version,method')
        config.set('subsection_http','encapsulation',False)

        config.add_section('subsection_udp')
        config.set('subsection_udp','key','udp')
        config.set('subsection_udp','keys','src,dst,offset,sport,dport,time')
        config.set('subsection_udp','encapsulation',False)

        config.add_section('subsection_dns')
        config.set('subsection_dns','key','dns')
        config.set('subsection_dns','keys','request,type,answers')
        config.set('subsection_dns','encapsulation',True)
        config.set('subsection_dns','subsections','answers')

        config.add_section('subsection_answers')
        config.set('subsection_answers','key','answers')
        config.set('subsection_answers','keys','type,data')
        config.set('subsection_answers','encapsulation',False)

        config.add_section('subsection_domains')
        config.set('subsection_domains','key','domains')
        config.set('subsection_domains','keys','domain,ip')
        config.set('subsection_domains','encapsulation',False)

        config.add_section('subsection_icmp')
        config.set('subsection_icmp','key','icmp')
        config.set('subsection_icmp','keys','src,dst,type,data')
        config.set('subsection_icmp','encapsulation',False)

        config.add_section('subsection_smtp')
        config.set('subsection_smtp','key','smtp')
        config.set('subsection_smtp','keys','dst,raw')
        config.set('subsection_smtp','encapsulation',False)
        # Writing configuration file to 'cuckoo_results.conf'
        print("Writing configuration file to 'cuckoo_results.conf'")
        with open(os.path.abspath(os.path.join(os.path.dirname(__file__),'conf','cuckoo_results.conf')), 'w') as configfile:
            config.write(configfile)
            configfile.close()
        print('Configuration Completed successfully')

    except Exception, e :
        print e

if __name__ == '__main__':
    main()
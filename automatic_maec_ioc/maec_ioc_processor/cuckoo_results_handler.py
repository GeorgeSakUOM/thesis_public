__author__ = 'george'
from ast import literal_eval
from common.configmanager import ConfigurationManager
from common.logger import Logger
import json,os
import errno
ANALYSIS_PATH=ConfigurationManager.readServerConfig(variable='analysis_path')
# Sections' names
S_ANALYSISINFO='analysisinfo'
S_PROCMEMORY='procmemory'
S_STATIC='static'
S_DROPPED = 'dropped'
S_BEHAVIOR = 'behavior'
S_STRINGS = 'strings'
S_DEBUG = 'debug'
S_MEMORY = 'memory'
S_TARGETINFO  = 'targetinfo'
S_VIRUSTOTAL = 'virustotal'
S_NETWORK = 'network'

def returnsubsections(flag,section,initiative=True,subsections=None):
    if flag and initiative:
        subsections += list(ConfigurationManager.readCuckooResultsConfig(variable='subsections',section=section).split(','))
        for subsection in subsections:
            subsections+=returnsubsections(flag=literal_eval(ConfigurationManager.readCuckooResultsConfig(variable='encapsulation',section='subsection_'+subsection)),
                              section='subsection_'+subsection,subsections=[],initiative=False)
        return subsections
    elif flag:
        subsections += list(ConfigurationManager.readCuckooResultsConfig(variable='subsections',section=section).split(','))
        for subsection in subsections:
            returnsubsections(flag=literal_eval(ConfigurationManager.readCuckooResultsConfig(variable='encapsulation',section='subsection_'+subsection)),
                              section='subsection_'+subsection,subsections=[],initiative=False)
        return subsections
    else:
        return subsections


def load_results(filename):
    results = None
    logger = Logger()
    try:
        dbfile = open(os.path.join(ANALYSIS_PATH,filename),'r')
        data = dbfile.read()
        results = json.loads(data)
        dbfile.close()
    except IOError, ioer :
        errorNum = ioer.errno
        errorCode = errno.errorcode[errorNum]
        errorString= os.strerror(errorNum)
        errorFile = ioer.filename
        info=(errorNum,errorCode,errorString,errorFile)
        logger.errorLogging(msg=info)
    except Exception, e :
        info = (str(e))
        logger.errorLogging(msg=info)
    return results

class Handler(object):

    def __init__(self,section,filename=None,data_results=None):
        self.logger = Logger()
        self.key=ConfigurationManager.readCuckooResultsConfig(variable='key',section=section)
        self.encapsulation = literal_eval(ConfigurationManager.readCuckooResultsConfig(variable='encapsulation',section=section))
        self.keys = list(ConfigurationManager.readCuckooResultsConfig(variable='keys',section=section).split(','))
        #Check if there are not any keys
        if self.keys==['']:
            self.keys=None
        self.subsectionskeys={}
        if self.encapsulation:
            self.subsections = returnsubsections(self.encapsulation,section=section,subsections=[])
            for subsection in self.subsections:
                self.subsectionskeys[ConfigurationManager.readCuckooResultsConfig(variable='key',section='subsection_'+subsection)] = list(ConfigurationManager.readCuckooResultsConfig(variable='keys',section='subsection_'+subsection).split(','))
        results=None
        try:
            if data_results is not None:
                results=data_results[self.key]
            elif filename is not  None:
                results = load_results(filename)[self.key]
        except Exception, e:
            self.logger.errorLogging(str(e))

        if isinstance(results,dict):
            self.dictionary = results
            self.list = None
        elif isinstance(results,list):
            self.list= results
            self.dictionary = None
        else:
            self.list = None
            self.dictionary = None

    def get_section_simple_values(self):
        values ={}
        if self.dictionary:
            for key in self.keys:
                if key in self.keys and key not in self.subsectionskeys.keys():
                    if key in self.dictionary.keys():
                       if not isinstance(self.dictionary[key],list):
                           values[key]= self.dictionary[key]
        return values

class AnalysisInfoHandler(Handler):

    def __init__(self,filename=None,data_results=None):
        super(AnalysisInfoHandler,self).__init__(section=S_ANALYSISINFO,filename=filename,data_results=data_results)

    def get_machine(self):
        return self.dictionary['machine']

class ProcessMemoryHandler(Handler):

    def __init__(self,filename=None,data_results=None):
        super(ProcessMemoryHandler,self).__init__(section=S_PROCMEMORY,filename=filename,data_results=data_results)

    def get_next_proc(self):
        if self.list:
            return self.list.pop(0)

    def get_yara(self,proc):
        if proc and proc is not None:
            return proc['yara']

class StaticHandler(Handler):

    def __init__(self,filename=None,data_results=None):
        super(StaticHandler,self).__init__(section=S_STATIC,filename=filename,data_results=data_results)

    def get_next_pe_import(self):
        if self.dictionary['pe_imports']:
            return self.dictionary['pe_imports'].pop(0)

    def get_next_pe_import_import(self,pe_import):
        if pe_import is not None:
            if pe_import['imports']:
                return pe_import['imports'].pop(0)

    def get_next_pe_exports(self):
        if self.dictionary['pe_exports']:
            return self.dictionary['pe_exportss'].pop(0)

    def get_next_pe_section(self):
        if self.dictionary['pe_sections']:
            return self.dictionary['pe_sections'].pop(0)

    def get_next_pe_resource(self):
        if self.dictionary['pe_resources']:
            return self.dictionary['pe_resources'].pop(0)

    def get_next_pe_versioninfo(self):
        if self.dictionary['pe_versioninfo']:
            return self.dictionary['pe_versioninfo'].pop(0)

class DroppedHandler(Handler):

    def __init__(self,filename=None,data_results=None):
        super(DroppedHandler,self).__init__(section=S_DROPPED,filename=filename,data_results=data_results)

    def get_next_drooped(self):
        if self.list:
            return self.list.pop(0)

    def get_yara(self,dropped):
        if dropped:
            return dropped['yara']

class BehaviorHandler(Handler):

    def __init__(self,filename=None,data_results=None):
        super(BehaviorHandler,self).__init__(section=S_BEHAVIOR,filename=filename,data_results=data_results)

    def get_next_process(self):
        if self.dictionary['processes']:
            return self.dictionary['processes'].pop(0)

    def get_next_process_call(self,process):
        if process is not None:
            if process['calls']:
                return process['calls'].pop(0)

    def get_next_process_call_argument(self,call):
        if  call is not None:
            if call['arguments']:
                return call['arguments'].pop(0)

    def get_next_process_tree_node(self):
        if self.dictionary['processtree']:
            return self.dictionary['processtree'].pop(0)

    def get_next_process_tree_node_children(self,node):
        if node is not None:
            if node['children']:
                return node['children'].pop(0)

    def get_next_anomaly(self):
        if self.dictionary['anomaly']:
            return self.dictionary['anomaly'].pop(0)

    def get_next_enhanced(self):
        if self.dictionary['enhanced']:
            return self.dictionary['enhanced'].pop(0)

    def get_enhanced_data(self,enhanced):
        if enhanced is not None:
            if enhanced['data']:
                return enhanced['data']
    def get_summary(self):
        if self.dictionary['summary']:
            return self.dictionary['summary']

class StringsHandler(Handler):

    def __init__(self,filename=None,data_results=None):
        super(StringsHandler,self).__init__(section=S_STRINGS,filename=filename,data_results=data_results)

    def get_next_string(self):
        if self.list:
            return self.list.pop(0)

class DebugHandler(Handler):

    def __init__(self,filename=None,data_results=None):
        super(DebugHandler,self).__init__(section=S_DEBUG,filename=filename,data_results=data_results)


    def get_next_error(self):
        if self.dictionary['errors']:
            return self.dictionary['errors'].pop(0)

class MemoryHandler(Handler):

    def __init__(self,filename=None,data_results=None):
        super(MemoryHandler,self).__init__(section=S_MEMORY,filename=filename,data_results=data_results)

    def get_subsection_next_item(self,subsection):
        if self.dictionary is not None:
            if self.dictionary[subsection]:
                if self.dictionary[subsection]['data']:
                    return self.dictionary[subsection]['data'].pop(0)

    def get_subsection_item_keys(self,subsection):
        return self.subsectionskeys[subsection+'_data']

    def get_subsection_config(self,subsection):
        if self.dictionary is not None:
            if self.dictionary[subsection]:
                return self.dictionary[subsection]['config']

class TargetInfoHandler(Handler):

    def __init__(self,filename=None,data_results=None):
        super(TargetInfoHandler,self).__init__(section=S_TARGETINFO,filename=filename,data_results=data_results)

    def get_file(self):
        if self.dictionary is not None:
            if 'file' in self.dictionary.keys():
                return self.dictionary['file']

    def get_next_file_yara(self):
        if self.dictionary is not None:
            if 'file' in self.dictionary.keys():
                if self.dictionary['file']['yara']:
                    return self.dictionary['file']['yara'].pop(0)

class VirusTotalHandler(Handler):
    def __init__(self,filename=None,data_results=None):
        super(VirusTotalHandler,self).__init__(section=S_VIRUSTOTAL,filename=filename,data_results=data_results)

    def get_next_scan(self):
        if self.dictionary is not None:
            if self.dictionary['scans']:
                keys = self.dictionary['scans'].keys()
                engine = keys.pop(0)
                signature = self.dictionary['scans'].pop(engine)
                return {engine:signature}

    def get_scan_analysis(self,scan):
        if scan is not None:
            return scan.values().pop(0)

class NetworkHandler(Handler):

    def __init__(self,filename=None,data_results=None):
        super(NetworkHandler,self).__init__(section=S_NETWORK,filename=filename,data_results=data_results)

    def get_next_irc(self):
        if self.dictionary is not None:
            if 'irc' in self.dictionary.keys():
                if self.dictionary['irc']:
                    return self.dictionary['irc'].pop(0)

    def get_next_host(self):
        if self.dictionary is not None:
            if 'hosts' in self.dictionary.keys():
                if self.dictionary['hosts']:
                    return self.dictionary['hosts'].pop(0)

    def get_next_domain(self):
        if self.dictionary is not None:
            if 'domains' in self.dictionary.keys():
                if self.dictionary['domains']:
                    return self.dictionary['domains'].pop(0)

    def get_next_tcp_flow(self):
        if self.dictionary is not None:
            if 'tcp' in self.dictionary.keys():
                if self.dictionary['tcp']:
                    return self.dictionary['tcp'].pop(0)

    def get_next_udp_flow(self):
        if self.dictionary is not None:
            if 'udp' in self.dictionary.keys():
                if self.dictionary['udp']:
                    return self.dictionary['udp'].pop(0)

    def get_next_icmp_packet(self):
        if self.dictionary is not None:
            if 'icmp' in self.dictionary.keys():
                if self.dictionary['icmp']:
                    return self.dictionary['icmp'].pop(0)

    def get_next_http_message(self):
        if self.dictionary is not None:
            if 'http' in self.dictionary.keys():
                if self.dictionary['http']:
                    return self.dictionary['http'].pop(0)

    def get_next_dns_query(self):
        if self.dictionary is not None:
            if 'dns' in self.dictionary.keys():
                if self.dictionary['dns']:
                    return self.dictionary['dns'].pop(0)

    def get_next_dns_query_answer(self,query):
        if query is not None:
            if query['answers']:
                return query['answers'].pop(0)

    def get_next_smtp_request(self):
        if self.dictionary is not None:
            if 'smtp' in self.dictionary.keys():
                if self.dictionary['smtp']:
                    return self.dictionary['smtp'].pop(0)

class AnalysisHandler():
    def __init__(self,filename=None,data_results=None):
        self.analysisinfo = AnalysisInfoHandler(filename=filename,data_results=data_results)
        self.procmemory = ProcessMemoryHandler(filename=filename,data_results=data_results)
        self.static = StaticHandler(filename=filename,data_results=data_results)
        self.dropped = DroppedHandler(filename=filename,data_results=data_results)
        self.behavior = BehaviorHandler(filename=filename,data_results=data_results)
        self.strings = StringsHandler(filename=filename,data_results=data_results)
        self.debug = DebugHandler(filename=filename,data_results=data_results)
        self.memory = MemoryHandler(filename=filename,data_results=data_results)
        self.targetinfo = TargetInfoHandler(filename=filename,data_results=data_results)
        self.virustotal = VirusTotalHandler(filename=filename,data_results=data_results)
        self.network = NetworkHandler(filename=filename,data_results=data_results)

if __name__=='__main__':
    an = AnalysisHandler(filename='cuckoo_results')
    #nh = NetworkHandler(filename='cuckoo_results')
    #print(nh.key)
    #print(nh.keys)
    #print(nh.subsections)
    #print(nh.get_section_simple_values())
    #print(nh.get_next_domain())
    #ti = TargetInfoHandler(filename='cuckoo_results')
    #print(ti.key)
    #print(ti.keys)
    #print(ti.subsections)
    #print(ti.subsectionskeys)
    #print(ti.dictionary)
    #print(ti.get_section_simple_values())
    #print(ti.get_file())
    #print(ti.get_next_file_yara())
    #infh=AnalysisInfoHandler(filename='cuckoo_results')
    #print(infh.key)
    #print(infh.keys)
    #print(infh.encapsulation)
    #print(infh.subsectionskeys)
    #print(infh.get_section_simple_values())
    #print(infh.get_machine())
    #pm = ProcessMemoryHandler(filename='cuckoo_results')
    #print(pm.key)
    #print(pm.keys)
    #print(pm.dictionary)
    #print(pm.get_yara())
    #st = StaticHandler(filename='cuckoo_results')
    #print(st.key)
    #print(st.dictionary)
    #print(st.get_section_simple_values())
    #print(st.get_next_pe_import())
    #print(st.get_next_pe_import_import(st.get_next_pe_import()))
    #print(st.get_next_pe_exports())
    #print(st.get_next_pe_section())
    #print(st.get_next_pe_resource())
    #print(st.get_next_pe_versioninfo())
    #print(st.get_next_pe_versioninfo())
    #dr = DroppedHandler(filename='cuckoo_results')
    #print(dr.key)
    #print(dr.get_section_simple_values())
    #print(dr.get_next_drooped())
    #print(dr.get_yara(dr.get_next_drooped()))
    #bh = BehaviorHandler(filename='cuckoo_results')
    #print(bh.key)
    #print(bh.get_section_simple_values())
    #print((bh.get_next_process()))
    #t=bh.get_next_process()
    #z=bh.get_next_process_call(t)
    #print(bh.get_next_process_call_argument(z))
    #node = bh.get_next_process_tree_node()

    #print(bh.get_next_process_tree_node_children(node))
    #print(bh.get_next_anomaly())
    #print(bh.get_next_enhanced())
    #print(bh.get_enhanced_data(bh.get_next_enhanced()))
    #print(bh.get_summary())
    #st =StringsHandler(filename='cuckoo_results')
    #print(st.key)
    #print(st.get_section_simple_values())
    #print(st.get_next_string())
    #db = DebugHandler(filename='cuckoo_results')
    #print(db.key)
    #print(db.get_section_simple_values())
    #print(db.get_next_error())
    vt= VirusTotalHandler(filename='cuckoo_results')
    print(vt.key)
    print(vt.subsections)
    print(vt.subsectionskeys)
    print(vt.get_section_simple_values())
    print(vt.get_next_scan())
    print(vt.get_scan_analysis(vt.get_next_scan()))
    #me = MemoryHandler(filename='cuckoo_results')
    #print(me.key)
    #print(me.subsections)
    #print(me.get_section_simple_values())
    #print(me.subsectionskeys)
    #print(me.get_subsection_item_keys('pslist'))
    #print(me.get_subsection_config('pslist'))
    #print(me.get_subsection_next_item('pslist'))
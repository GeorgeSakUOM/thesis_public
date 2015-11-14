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
    def __init__(self,section,filename):
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
        results = load_results('cuckoo_results')[self.key]
        if isinstance(results,dict):
            self.dictionary = results
            self.list = None
        elif isinstance(results,list):
            self.list= results
            self.dictionary = None

    def get_section_simple_values(self):
        values ={}
        if self.dictionary:
            for key in self.keys:
                if key in self.keys and key not in self.subsectionskeys.keys():
                    values[key]= self.dictionary[key]
        return values

class AnalysisInfoHandler(Handler):

    def __init__(self,filename):
        super(AnalysisInfoHandler,self).__init__(section=S_ANALYSISINFO,filename=filename)

    def get_machine(self):
        return self.dictionary['machine']

class ProcessMemoryHandler(Handler):

    def __init__(self,filename):
        super(ProcessMemoryHandler,self).__init__(section=S_PROCMEMORY,filename=filename)

    def get_next_proc(self):
        if self.list:
            return self.list.pop(0)

    def get_yara(self,proc):
        if proc and proc is not None:
            return proc['yara']

class StaticHandler(Handler):

    def __init__(self,filename):
        super(StaticHandler,self).__init__(section=S_STATIC,filename=filename)

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

    def __init__(self,filename):
        super(DroppedHandler,self).__init__(section=S_DROPPED,filename=filename)

    def get_next_drooped(self):
        if self.list:
            return self.list.pop(0)

    def get_yara(self,dropped):
        if dropped:
            return dropped['yara']

class BehaviorHandler(Handler):

    def __init__(self,filename):
        super(BehaviorHandler,self).__init__(section=S_BEHAVIOR,filename=filename)

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

    def __init__(self,filename):
        super(StringsHandler,self).__init__(section=S_STRINGS,filename=filename)

    def get_next_string(self):
        if self.list:
            return self.list.pop(0)

class DebugHandler(Handler):

    def __init__(self,filename):
        super(DebugHandler,self).__init__(section=S_DEBUG,filename=filename)


    def get_next_error(self):
        if self.dictionary['errors']:
            return self.dictionary['errors'].pop(0)

class MemoryHandler(Handler):
    pass

class TargetInfoHandler(Handler):
    pass

class VirusTotalHandler(Handler):
    def __init__(self,filename):
        super(VirusTotalHandler,self).__init__(section=S_VIRUSTOTAL,filename=filename)

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
    pass


class AnalysisHandler():
    def __init__(self,filename):
        self.analysisinfo = AnalysisInfoHandler(filename=filename)





if __name__=='__main__':
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

__author__ = 'george'
from ast import literal_eval
from common.configmanager import ConfigurationManager
ANALYSIS_PATH=ConfigurationManager.readServerConfig(variable='analysis_path')

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


class Handler(object):
    def __init__(self,key,encapsulation):
        self.key=key
        self.encapsulation = encapsulation

class AnalysisInfoHandler(Handler):
    def __init__(self,analysisinfo,dictionary,section='analysisinfo'):
        super(AnalysisInfoHandler,self).__init__(ConfigurationManager.readCuckooResultsConfig(variable='key',section=section),
                                                 bool(ConfigurationManager.readCuckooResultsConfig(variable='encapsulation',section=section)))
        self.keys = list(ConfigurationManager.readCuckooResultsConfig(variable='keys',section=section).split(','))
        if self.encapsulation:
            self.subsections = returnsubsections(self.encapsulation,section=section,subsections=[])
            self.subsectionskeys={}
            for subsection in self.subsections:
                self.subsectionskeys[subsection] = list(ConfigurationManager.readCuckooResultsConfig(variable='keys',section='subsection_'+subsection).split(','))




class AnalysisHandler(Handler):

    def __init__(self,path,key):
        super(AnalysisHandler,self).__init__(key)
        path=path






if __name__=='__main__':
    infh=AnalysisInfoHandler({})
    print(infh.key)
    print(infh.keys)
    print(infh.encapsulation)
    print(infh.subsectionskeys)
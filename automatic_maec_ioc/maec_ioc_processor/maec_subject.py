'''
@author: george
'''
from cuckooResultsHandler import CuckooResultsHandler
from maec.package.malware_subject import MalwareSubject
from maec.utils.idgen import IDGenerator
from maec.utils.nsparser import Namespace
from common.xmlhandler import XMLhandler
#testing
import json
class MAECSubject():
    '''
    classdocs
    '''


    def __init__(self, results,namespace_='',prefix=''):
        '''
        Constructor
        '''
        self.handler = CuckooResultsHandler(results)
        self.idgen = IDGenerator()
        self.malwaresubject = MalwareSubject()
        self.setSubjectId(namespace=namespace_,prefix_=prefix)
    
    def setSubjectId(self,namespace='',prefix_='bundle'):
        '''
        The given namespace should be had the form xmlns:prefix="URI"
        '''
        if namespace=='':
            self.malwaresubject.id_ = self.idgen.create_id(prefix=prefix_)
        else:
            mixedname =''.join(namespace.split(':')[1:])
            name = mixedname.split('=')[1]
            px=mixedname.split('=')[0]
            ns = Namespace(name=name,prefix=px)
            self.idgen._namespace=ns
            self.malwaresubject.id_ = self.idgen.create_id(prefix=prefix_)   
            
    def setsubjectLabel(self):
        ms.malwaresubject.label = ''
        pass
        
        
        
if __name__ =='__main__':
    dbfile = open('../analysis_hub/cuckoo_results','r')
    data = dbfile.read()
    resultsDictionary = json.loads(data)
    dbfile.close()
    ms = MAECSubject(resultsDictionary)
    print(ms.malwaresubject.to_xml())
    

'''
@author: george
'''
from cuckooResultsHandler import CuckooResultsHandler
from maec.bundle.bundle import Bundle
from maec.utils.idgen import IDGenerator
from cybox.utils.nsparser import Namespace
from maec.bundle.av_classification import AVClassification 
from cybox.core import Object
from cybox.objects.file_object import File
from datetime import datetime
from common.xmlhandler import XMLhandler
from common.default_dict import maecEnumFiles
import os
#testing imports
import json


class MAECBundle():
    '''
    classdocs
    '''
    def __init__(self, results) :
        '''
        Constructor
        '''
        self.handler = CuckooResultsHandler(results)
        self.bundle = Bundle()
        self.idgen = IDGenerator()
        self.av_classifications = AVClassification()
    
    def bundleAttributesCreator(self,defined_subject=True,content_type='',timestamp=datetime.now(),namespace=''):
        '''
        This method initialize all maec attributes.
        The given namespace should be had the form xmlns:prefix="URI"
        The defined_subject is by default True except the case that subject's attributes are defined in a package instance. 
        The content_type is auto-initialized when the bundle created from an automated tool.  
        '''
        if namespace=='':
            self.bundle.id_ = self.idgen.create_id(prefix='bundle')
        else:
            mixedname =''.join(namespace.split(':')[1:])
            name = mixedname.split('=')[1]
            prefix=mixedname.split('=')[0]
            ns = Namespace(name=name,prefix=prefix)
            self.idgen._namespace=ns
            self.bundle.id_ = self.idgen.create_id(prefix='bundle')    
        
        self.bundle.defined_subject =defined_subject
        
        if self.handler.basicmodules :
            self.bundle.content_type = XMLhandler.returnListofValuesS(maecEnumFiles['BundleContentTypeEnum'])[0]
        else:
            self.bundle.content_type = content_type
        
        self.bundle.timestamp =timestamp
        
    def bundleMalwareInstanceObjectAttributes(self):
        sample=Object()
        sample.properties = File()
        
        self.bundle.set_malware_instance_object_atttributes(sample)
   
    def bundleAVClassifications(self):
        self.bundle.av_classifications =self.av_classifications
        pass
    def bundleProcessTree(self):
        pass
    def bundleCapabilities(self):
        pass
    def bundleBehaviors(self):
        pass
    def bundleActions(self):
        pass
    def bundleObjects(self):
        pass
    def bundleCandidateIndicators(self):
        pass
    def bundleCollections(self):
        pass
     
    
        
        
        
if __name__=='__main__':
    dbfile = open('../analysis_hub/cuckoo_results','r')
    data = dbfile.read()
    resultsDictionary = json.loads(data)
    dbfile.close()
    print(Bundle.schema_version)
    #print(resultsDictionary.keys())
    testob = MAECBundle(resultsDictionary)
    testob.bundleAttributesCreator(namespace='xmlns:h="http://www.w3.org/TR/html4')
    testob.bundleMalwareInstanceObjectAttributes()
    print(testob.bundle.to_xml('', '', ''))
    print(testob.idgen.namespace)
    
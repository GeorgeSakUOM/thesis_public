'''
@author: george
'''
from cuckooResultsHandler import CuckooResultsHandler

BUNDLES_PATH = 

'''
from cybox.core import AssociatedObjects, AssociatedObject, Object, AssociationType
from cybox.common import Hash, HashList, VocabString
from cybox.objects.file_object import File
from maec.bundle import Bundle, Collections, MalwareAction, Capability
from maec.package import Analysis, MalwareSubject, Package
from cybox.utils import Namespace
import maec.utils
'''
'''
testing imports
'''
import json

class MAECCreator():
    '''
    classdocs
    '''

    def __init__(self, results):
        self.handler = CuckooResultsHandler(results)
    
           
if __name__=='__main__':
    pass
'''
@author: george
'''
from cuckooResultsHandler import CuckooResultsHandler
from common.configmanager import ConfigurationManager
from maec_bundle import import MAECBundle
from maec_container import MAECContainer
from maec_package import MAECPackage 

BUNDLES_PATH = ConfigurationManager.readmaecConfig(variable='maec_path_bundles')
PACKAGES_PATH = ConfigurationManager.readmaecConfig(variable='maec_path_packages')
CONTAINERS_PATH = ConfigurationManager.readmaecConfig(variable='maec_path_containers')
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
    print(BUNDLES_PATH)
    print(CONTAINERS_PATH)
    print(PACKAGES_PATH)
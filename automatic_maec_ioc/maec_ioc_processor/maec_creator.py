'''
@author: george
'''
from common.configmanager import ConfigurationManager
from maec_bundle import MAECBundle
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

class MAECCreator():
    '''
    Creates any type of maec product(bundle,package,container)
    '''

    def __init__(self, results,bundles_path =BUNDLES_PATH,packages_path=PACKAGES_PATH,containers_path =CONTAINERS_PATH):
        self.bundles_path =bundles_path
        self.packages_path = packages_path
        self.containers_path = containers_path
        self.bundle = MAECBundle(results)
        self.container = MAECContainer
        self.package = MAECPackage
           
if __name__=='__main__':
    print(BUNDLES_PATH)
    print(CONTAINERS_PATH)
    print(PACKAGES_PATH)
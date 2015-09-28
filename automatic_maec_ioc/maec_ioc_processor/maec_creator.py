'''
@author: george
'''
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
        self.results = results
    
    # Get functions divide results dictionary in its basic attributes
    
    def getBasicResultsModules(self):
        basicmodules = self.results.keys()
        self.basicmodules = basicmodules
    # Handles the info module of results 
    def getInfoResultsKeys(self):
        infoKeys = self.results[self.basicmodules[0]].keys()
        return infoKeys
    
    def getMachineKeys(self):
        if 'machine' in self.getInfoResultsKeys():
            return self.results[self.basicmodules[0]]['machine'].keys()
    
    def getInfoDict(self):
        return self.results[self.basicmodules[0]]
        
        
    def getMachineDict(self):
        if 'machine' in self.getInfoResultsKeys():
            return self.results[self.basicmodules[0]]['machine']
    
    # Handles the procmemory module of results
    def getProcmemoryList(self):
        return self.results[self.basicmodules[1]]
    
    # Handles the network module of results
    
    def getNetworkDictKeys(self):
        return self.results[self.basicmodules[2]].keys()
    
    def getNetworkDict(self):
        return self.results[self.basicmodules[2]]
    
    # Handles the virustotal module of results
    def getVirusTotalKeys(self):
        pass
    
    def getVirusTotalDict(self):
        pass
    
    def getScanVTKeys(self):
        pass
    
    def getAntiVirusVendorKeys(self):
        pass
    
    def getAntiVirusVendorDict(self):
        pass
    # Handles the signatures module of results
    # Handles the static module of results
    # Handles the dropped module of results
    # Handles the behavior module of results
    # Handles the debug module of results
    # Handles the strings module of results
    # Handles the target module of results
    

if __name__=='__main__':
    print('Starting test')
    
    dbfile = open('../analysis_hub/cuckoo_results','r')
    data = dbfile.read()
    resultsDictionary = json.loads(data)
    dbfile.close()
    
    maec = MAECCreator(resultsDictionary)
    maec.getBasicResultsModules()
    '''
    print('Printing  basic modules')
    print(maec.basicmodules)
    print('Printing info keys')
    print(maec.getInfoResultsKeys())
    print('Printing info dict')
    print(maec.getInfoDict())
    print('Printing machine keys')
    print(maec.getMachineKeys())
    print('Printing machine dict')
    print(maec.getMachineDict())
    print('Printing procmemory list') 
    print(maec.getProcmemoryList())
    print('Printing Network Dict')
    
    print(maec.getNetworkDict())
    '''
    keys = resultsDictionary.keys()
    print(keys)
    virustotal = resultsDictionary[keys[3]]
    print('Printing virustotal')
    print(keys[3])
    print(virustotal.keys())
    print(virustotal)
    dkeys=[]
    for key in virustotal.keys():
        if type(virustotal[key]) is dict:
            dkeys.append(key)
    print(dkeys)
    print(virustotal[dkeys[0]].keys())
    for key  in  virustotal[dkeys[0]].keys():
        print(key)
        if type(virustotal[dkeys[0]][key]) is dict:
            print(virustotal[dkeys[0]][key].keys())
            for key1 in virustotal[dkeys[0]][key].keys():
                print(virustotal[dkeys[0]][key][key1])
        else:
            print(virustotal[dkeys[0]][key])
    
    '''
    for key in keys:
        print(key+':\n')
    '''    
        
        
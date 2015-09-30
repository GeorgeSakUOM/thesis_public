'''
@author: george
'''

class CuckooResultsHandler():
    '''
    CuckooResultsHandler handles results objects received from cuckoo sandbox
    '''

    def __init__(self, results):
        self.results = results
        self.getBasicResultsModules()
    # Get functions divide results dictionary in its basic attributes
    
    def getBasicResultsModules(self):
        basicmodules = self.results.keys()
        self.basicmodules = basicmodules
        
    # Handles the info module of results 
    def getInfoDict(self):
        return self.results[self.basicmodules[0]]
    
    def getInfoDictKeys(self):
        infoKeys = self.getInfoDict().keys()
        return infoKeys
              
    def getMachineDict(self):
        if 'machine' in self.getInfoResultsKeys():
            return self.getInfoDict()['machine']
  
    def getMachineKeys(self):
        if 'machine' in self.getInfoResultsKeys():
            return self.getMachineDict().keys()  
    
    # Handles the procmemory module of results
    def getProcmemoryList(self):
        return self.results[self.basicmodules[1]]
    
    # Handles the network module of results
    
    def getNetworkDict(self):
        return self.results[self.basicmodules[2]]
    
    def getNetworkDictKeys(self):
        return self.getNetworkDict().keys()
    
    # Handles the static module of results
    def getVirusTotalDict(self):
        return self.results[self.basicmodules[3]]
    
    def getVirusTotalKeys(self):
        return self.getVirusTotalDict().keys()
    
    def getScanVTKeys(self):
        if 'scans' in self.getVirusTotalKeys():
            return self.getVirusTotalDict()['scans'].keys()    
    
    def getAntiVirusVendorKeys(self):
        return self.getVirusTotalDict()['scans'][self.getScanVTKeys()[1]].keys()
    
    def getAntiVirusVendorDict(self,vendor):
        return self.getVirusTotalDict()['scans'][vendor]
    
    # Handles the signatures module of results
    def getSignaturesList(self):
        return self.results[self.basicmodules[4]]
    
    # Handles the static module of results
    
    def getStaticDict(self):
        return self.results[self.basicmodules[5]]
    
    def getStaticKeys(self):
        return self.getStaticDict().keys()
    
    def getStaticInternalModuleList(self,module):
        return self.getStaticDict()[module]
    
    def getStaticInternalModListDictKeys(self,index,module):
        return self.getStaticInternalModuleList(module)[index].keys()

    def getStaticInternalModListDict(self,index,module):
        return self.getStaticInternalModuleList(module)[index]
    
    def getStaticInternalModListDictList(self,index,module,module1):
        return self.getStaticInternalModListDict(index, module)[module1]
    
    # Handles the dropped module of results
    def getDroppedList(self):
        return self.results[self.basicmodules[6]]
    
    def getDroppedListItem(self,index):
        return self.getDroppedList()[index]
    
    def getDroppedListItemKeys(self,index):
        if type(self.getDroppedListItem(index)) is dict:
            return self.getDroppedListItem(index).keys()
        else:
            print("It isn't dictionary")

    # Handles the behavior module of results
    def getBehaviorDict(self):
        return self.results[self.basicmodules[7]]
    
    def getBehaviorDictKeys(self):
        return self.getBehaviorDict().keys()
    
    def getBehaviorDictList(self,index):
        if type(self.getBehaviorDict()[index]) is list:
            return self.getBehaviorDict()[index]
        else:
            print("It isn't a list")
    
    def getBehaviorDict2(self,index):
        if type(self.getBehaviorDict()[index]) is dict:
            return self.getBehaviorDict()[index]
        else:
            print("It isn't a lsit")
    
    # Handles the debug module of results
    def getDebugDict(self):
        return self.results[self.basicmodules[8]]
    
    def getDebugKeys(self):
        return self.getDebugDict().keys()
    
    # Handles the strings module of results
    def getStringsList(self):
        return self.results[self.basicmodules[9]]
    
    # Handles the target module of results
    def getTargetDict(self):
        return self.results[self.basicmodules[10]]
    
    def getTargetDictKeys(self):
        return self.getTargetDict().keys()
    
    def getTargetInternalDict(self):
        for key in self.getTargetDictKeys(): 
            if type(self.getTargetDict()[key]) is dict:return self.getTargetDict()[key]
    
    def getTargetInternalDictKeys(self):
        return self.getTargetInternalDict().keys()

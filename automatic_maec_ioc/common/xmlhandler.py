'''
@author: george
'''
import os
from configmanager import ConfigurationManager
from xml.etree import ElementTree
XML_PATH = ConfigurationManager.readxmlConfig(variable='xml_path')
XML_CREATED_PATH=os.path.join(XML_PATH,'xml_created')

class XMLhandler():
    '''
    Class XMLhandler load an xml file and manage it.
    '''


    def __init__(self, filename=None):
        self.filepath= os.path.join(XML_CREATED_PATH,filename)
        self.etree = ElementTree.parse(self.filepath)
        
    def returnListofValuesC(self):
        '''
        XMLhandler method return a list of values from an xml file
        '''
        values =[]
        for value in self.etree.findall('./'):
            values.append(value.text)
        return values
    
    def returnDictofValuesC(self):
        '''
        XMLhandler method return a dict of values from an xml file
        '''
        values ={}
        for value in self.etree.findall('./'):
            values[value.text]=value.text
        return values
    
    @staticmethod
    def returnListofValuesS(filename):
        '''
        XMLhandler static method return a list of values from an xml file
        '''
        filepath= os.path.join(XML_CREATED_PATH,filename)
        etree = ElementTree.parse(filepath)
        values =[]
        for value in etree.findall('./'):
            values.append(value.text)
        return values
    
    @staticmethod
    def returnDictofValuesS(filename):
        '''
        XMLhandler static method return a dict of values from an xml file
        '''
        filepath= os.path.join(XML_CREATED_PATH,filename)
        etree = ElementTree.parse(filepath)
        values ={}
        for value in etree.findall('./'):
            values[value.text]=value.text
        return values
    
    
if __name__=='__main__':
    #testing 
    dictfile=open(os.path.join(XML_PATH,'files_dictionary.json'),'r').read()
    import json
    filesdict= json.loads(dictfile)


    print(XMLhandler.returnListofValuesS(filesdict['AnalysisMethodEnum']))

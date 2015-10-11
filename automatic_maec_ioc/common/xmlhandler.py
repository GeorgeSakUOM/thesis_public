'''
@author: george
'''
import os
from configmanager import ConfigurationManager
from xml.etree import ElementTree
from default_dict import maecEnumFiles
XML_PATH = ConfigurationManager.readxmlConfig(variable='xml_path')

class XMLhandler():
    '''
    Class XMLhandler load an xml file and manage it.
    '''


    def __init__(self, filename=''):
        self.filepath= os.path.join(XML_PATH,filename)
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
        filepath= os.path.join(XML_PATH,filename)
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
        filepath= os.path.join(XML_PATH,filename)
        etree = ElementTree.parse(filepath)
        values ={}
        for value in etree.findall('./'):
            values[value.text]=value.text
        return values
    
    
if __name__=='__main__':
    #testing 
    print(XMLhandler.returnListofValuesS(maecEnumFiles['BundleContentTypeEnum']))   

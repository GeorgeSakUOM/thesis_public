__author__ = 'george'
import os,json
from xml.etree import ElementTree as ET
from common.configmanager import ConfigurationManager

SOURCE_PATH =ConfigurationManager.readxmlConfig(variable='xsd_source_path')
DESTINATION_PATH =ConfigurationManager.readxmlConfig(variable='xml_created_path')
SCHEMA_FILE_PATH = os.path.join(os.getcwd(),'EnumList.xsd')

def extract_files(source_path):
    dict={}
    for dirpath, dirnames,files in  os.walk(source_path):
        if files and (all('py' not in name for name in files)):
            dict[dirpath]=files
    return dict

def print_enumeration_values_from_file(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()
    for child in root:
        flag=False
        if 'name' in child.attrib.keys() and ('Enum' in child.attrib['name']or 'List' in child.attrib['name']):
            if any('restriction' in x.tag for x in child):
                for x in child:
                    if 'restriction' in x.tag and list(x):
                        flag=True
                if flag:
                    print(child.attrib['name'])
                    print('-------------------------------------------------------------')
                    for child1 in child:
                        if 'restriction' in child1.tag:
                            for child2 in child1:
                                print(child2.attrib['value'])
                    print('+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++')

def write_elements_to_schema_file(schema_file_path,file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()
    schema_tree = ET.parse(schema_file_path)
    schema_root =schema_tree.getroot()
    for child in root:
        flag=False
        if 'name' in child.attrib.keys() and ('Enum' in child.attrib['name']or 'List' in child.attrib['name']):
            if any('restriction' in x.tag for x in child):
                for x in child:
                    if 'restriction' in x.tag and list(x):
                        flag=True
                if flag:
                   ET.SubElement(schema_root,tag='xs:element',attrib={'name':child.attrib['name'],'type':'EnumList'})
    schema_tree.write(SCHEMA_FILE_PATH)

def create_xml_empty_files(file_path,destination_directory):
    tree = ET.parse(file_path)
    root = tree.getroot()
    for child in root:
        flag=False
        if 'name' in child.attrib.keys() and ('Enum' in child.attrib['name']or 'List' in child.attrib['name']):
            if any('restriction' in x.tag for x in child):
                for x in child:
                    if 'restriction' in x.tag and list(x):
                        flag=True
                if flag:
                    f = open(os.path.join(destination_directory,child.attrib['name']+'.xml'),'w')
                    f.close()

def write_xml_files(file_path,destination_directory):
    tree = ET.parse(file_path)
    root = tree.getroot()
    for child in root:
        flag=False
        if 'name' in child.attrib.keys() and ('Enum' in child.attrib['name']or 'List' in child.attrib['name']):
            if any('restriction' in x.tag for x in child):
                for x in child:
                    if 'restriction' in x.tag and list(x):
                        flag=True
                if flag:
                    xml_element = ET.Element(tag=child.attrib['name'],attrib={'xmlns':'http://www.w3schools.com','xmlns:xsi':'http://www.w3.org/2001/XMLSchema-instance',
                                                                    'xsi:schemaLocation':'http://www.w3schools.com','file':'EnumList.xsd'})
                    for child1 in child :
                        for child2 in child1:
                            if 'enum' in  child2.tag:
                                xml_subelement = ET.SubElement(xml_element,tag='enum')
                                xml_subelement.text=child2.attrib['value']
                    et =ET.ElementTree()
                    et._setroot(element=xml_element)
                    et.write(os.path.join(destination_directory,child.attrib['name']+'.xml'),encoding="UTF-8",method='xml')

def run(source_path,schema_file_path,destination_directory):
    dict = extract_files(source_path)
    for key in dict.keys():
        for value in dict[key]:
            path =os.path.join(key,value)
            write_elements_to_schema_file(schema_file_path=schema_file_path,file_path=path)
            create_xml_empty_files(file_path=path,destination_directory=destination_directory)
            write_xml_files(file_path=path,destination_directory=destination_directory)
            print(path)
        print('-------------------------------------------------------------')

def write_file_names_to_a_dictionary(new_file_path,source_path):
    with open(new_file_path,'w') as dfile:
        data={}
        for dirpath,dirname,files in os.walk(source_path):
            for file in files:
                data[file.split('.')[0]]=file
                print(file.split('.')[0]+' : '+file)
        print(str(data))
        json.dump(data,dfile)


if __name__=='__main__':

    run(source_path=SOURCE_PATH,schema_file_path=SCHEMA_FILE_PATH,destination_directory=DESTINATION_PATH)
    write_file_names_to_a_dictionary('files_dictionary.json',DESTINATION_PATH)

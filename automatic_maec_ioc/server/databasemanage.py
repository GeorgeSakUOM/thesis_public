'''
Created on 10 Δεκ 2014

@author: george
'''

from pymongo.mongo_client import MongoClient
URL='localhost'
DB_NAME='iocDatabase'
class DatabaseManager(object):
    '''
    A DatabaseManager is used for the establishment of a connection with the mongoDB database. Offer CRUD operations via functions.   
    '''

    def __init__(self, cl=MongoClient(URL,27017),DB_NAME):
        client=cl; 
        database=client[DB_NAME]
        
    def insert(self,xml_page):
        pass
        
    def delete(self,xml_index):
        pass

    def search(self,xml_index):
        pass
    
    def update(self,xml_index, parameters_list):
        pass
    
    
    
    
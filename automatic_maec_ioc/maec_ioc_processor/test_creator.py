__author__ = 'george'

from cuckoo_results_handler import Handler
from common.configmanager import ConfigurationManager
from cuckoo_results_handler import Handler
from cuckoo_results_handler import load_results
import  os
import json
path= ConfigurationManager.readServerConfig(variable='analysis_path')
filename='cuckoo_results'

filepath = os.path.join(path,filename)
data = load_results(filepath)


if __name__ =='__main__':
    import datetime
    print(datetime.date.today())
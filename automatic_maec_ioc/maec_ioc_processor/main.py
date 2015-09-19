'''

@author: george
'''

if __name__ == '__main__':
    #print MAEC_Bundle.maecBundle
    '''
    filename ='../server_client/cuckoo_results'
    
    res = open(filename,'r')
    dictstr = res.read()
    diction = eval(dictstr)
    # keys = diction.keys()
    #for key in keys:
    #   print(key)
    '''
    diction = {'1':'foo1','2':'fffo1'}
    test =str(diction)
    newdict = eval(test)
    print(newdict['1'])
__author__ = 'george'

from mixbox.idgen import IDGenerator,set_id_namespace, set_id_method
from cybox.core import Observables


class CyboxObservables(Observables):

    def __init__(self,observables=None):
        super(CyboxObservables,self).__init__(observables=observables)



    def addObservables(self,observable):
        self.add(observable=observable)




if __name__=='__main__':
    from cybox_object import CyboxObject
    from cybox_observable import CyboxObservable

    ex = CyboxObject()
    ex.objecttype.file_name='example'
    co1 = CyboxObservable(item=ex.objecttype)
    ex1 = CyboxObject()
    ex1.objecttype.file_name='example3'
    co2 = CyboxObservable(item=ex1.objecttype)
    #test1= CyboxObservables(observables=[co1,co2])
    test1= CyboxObservables()
    test1.add(co1)
    test1.add(co2)
    print(test1.to_xml())

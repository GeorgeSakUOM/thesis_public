__author__ = 'george'

from mixbox.idgen import IDGenerator,set_id_namespace, set_id_method
from cybox.core import Observable, ObservableComposition,Object, Event


class CyboxObservable(Observable):

    def __init__(self,item=None,id=None,idref=None,description=None,namespace=None):
        set_id_method(IDGenerator.METHOD_UUID)
        if namespace is not None:
            set_id_namespace(namespace)
        super(CyboxObservable,self).__init__(item=item,id_=id,idref=idref,title=None, description=description)



    def addObservable(self,observable):
        '''
        :param observable: Should be of type Object or ObservableComposition or Event or ObjectProperties
        '''
        if isinstance(observable,Object):
            self.object_(observable)
        elif isinstance(observable,ObservableComposition):
            self.observable_composition(observable)
        elif isinstance(observable,Event):
            self.event(observable)





if __name__=='__main__':
    from cybox_object import CyboxObject

    ex = CyboxObject()
    ex.objecttype.file_name='example'
    co = CyboxObservable(item=ex.objecttype)

    print(co.to_xml())
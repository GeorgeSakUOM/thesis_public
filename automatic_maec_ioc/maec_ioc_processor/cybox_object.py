__author__ = 'george'

from cybox.core import Object
from cybox.objects.file_object import File

class CyboxObject(Object):

    def __init__(self,objecttype =File):
        self._objecttype = objecttype()

    @property
    def objecttype(self):
        return self._objecttype

    @objecttype.setter
    def objecttype(self,value):
        self._objecttype = value

    def to_xml(self):
        return self.objecttype.to_xml()


if __name__=='__main__':
    ex = CyboxObject()

    print(ex.to_xml())
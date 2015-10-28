from maec.package import Package



class MaecPackage(Package):


    def __init__(self,id=None,timestamp=None,schema_version="2.1",malware_subjects=None,grouping_relationships=None):
        super(MaecPackage,self).__init__(id=id,schema_version=schema_version,timestamp=timestamp)
        self.timestamp =None
        self.malware_subjects =malware_subjects
        self.id_ =id
        self.schema_version=schema_version
        self.grouping_relationships = grouping_relationships
        #+methods
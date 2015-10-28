from maec.package import Package,GroupingRelationship, ClusteringMetadata,ClusteringAlgorithmParameters,ClusterComposition,ClusterEdgeNodePair
from mixbox.idgen import set_id_namespace,set_id_method,IDGenerator
from maec_malware_subject import MaecMalwareSubject
from cybox.common import VocabString

class MaecPackage(Package):


    def __init__(self,id=None,timestamp=None,schema_version="2.1",malware_subjects=None,grouping_relationships=None,namespace=None):

        if namespace is not None:
            set_id_method(IDGenerator.METHOD_UUID)
            set_id_namespace(namespace)
        super(MaecPackage,self).__init__(id=id,schema_version=schema_version,timestamp=timestamp)
        if malware_subjects is not None:
            for malware_subject in malware_subjects:
                if isinstance(malware_subject,MaecMalwareSubject):
                    self.add_malware_subject(malware_subject=malware_subject)
        if grouping_relationships is not None:
            for grouping_relationship in grouping_relationships:
                if isinstance(grouping_relationship,GroupingRelationship):
                    self.add_grouping_relationship(grouping_relationship=grouping_relationship)

    def creategroupingrelationship(self,type=None,malware_toolkit_name=None,malware_family_name=None,clustering_metadata=None):
        grouping_relationship = GroupingRelationship()
        grouping_relationship.type_ = VocabString(type)
        grouping_relationship.malware_toolkit_name = malware_toolkit_name
        grouping_relationship.malware_family_name = malware_family_name
        grouping_relationship.clustering_metadata = clustering_metadata
        return grouping_relationship

    def creategroupingrelationshipclusteringmetadata(self,cluster_size=None,cluster_description=None,cluster_composition=None,algorithm_version=None,
                                                     algorithm_parameters=None,algorithm_name=None):
        clustering_metadata = ClusteringMetadata()
        clustering_metadata.cluster_size =cluster_size
        clustering_metadata.cluster_description =cluster_description
        clustering_metadata.cluster_composition = cluster_composition
        clustering_metadata.algorithm_version=algorithm_version
        clustering_metadata.algorithm_parameters =algorithm_parameters
        clustering_metadata.algorithm_name = algorithm_name
        return clustering_metadata

    def creategroupingrelationshipclusteringmetadataalgorithmparameters(self,number_of_iterations=None,distancethreashold=None):
        #library bug distance threashold
        parameter = ClusteringAlgorithmParameters()
        parameter.number_of_iterations =number_of_iterations
        parameter.distance_threashold=distancethreashold
        return parameter

    def creategroupingrelationshipclusteringmetadataclusteringcomposition(self,score_type=None,edge_node_pair=None):
        cluster_composition = ClusterComposition()
        cluster_composition.edge_node_pair =edge_node_pair
        cluster_composition.score_type = score_type
        return cluster_composition

    def creategroupingrelationshipclusteringmetadataclusteringcompositionedgenodepair(self,similarity_index=None,similarity_distance = None,malware_subject_node_a=None,
                                                                                      malware_subject_node_b=None):
        edge_node_pair = ClusterEdgeNodePair()
        edge_node_pair.similarity_index = similarity_index
        edge_node_pair.similarity_distance = similarity_distance
        edge_node_pair.malware_subject_node_a = malware_subject_node_a
        edge_node_pair.malware_subject_node_b = malware_subject_node_b
        return edge_node_pair

if __name__ =='__main__':
    #Testing example
    from mixbox.namespaces import Namespace
    import datetime
    pa = MaecPackage(namespace=Namespace('testnamespace','totest','testschemalocation'),timestamp=datetime.datetime.now())
    ####################################################################################################################
    #Add malware subjects
    ms1 = MaecMalwareSubject()
    ms2 = MaecMalwareSubject()
    pa.add_malware_subject(ms1)
    pa.add_malware_subject(ms2)
    ####################################################################################################################
    #Add relationships
    from maec.package import MalwareSubjectReference
    mr1 = MalwareSubjectReference(malware_subject_idref='test idref 1')
    mr2 = MalwareSubjectReference(malware_subject_idref='test idref 2')
    enp = pa.creategroupingrelationshipclusteringmetadataclusteringcompositionedgenodepair(similarity_distance=0.45,similarity_index=12.3,malware_subject_node_a=mr1,malware_subject_node_b=mr2)
    mr3 = MalwareSubjectReference(malware_subject_idref='test idref 3')
    mr4 = MalwareSubjectReference(malware_subject_idref='test idref 4')
    enp1 = pa.creategroupingrelationshipclusteringmetadataclusteringcompositionedgenodepair(similarity_distance=0.13,similarity_index=14.3,malware_subject_node_a=mr3,malware_subject_node_b=mr4)

    cc = pa.creategroupingrelationshipclusteringmetadataclusteringcomposition(score_type='Test score type',edge_node_pair=[enp,enp1])
    par = pa.creategroupingrelationshipclusteringmetadataalgorithmparameters(number_of_iterations=14444,distancethreashold=0.15)
    cm = pa.creategroupingrelationshipclusteringmetadata(algorithm_name='Test clustering algorithm name',algorithm_version='2.1',cluster_description='Test cluster description',
                                                         cluster_size=1500,algorithm_parameters=par,cluster_composition=cc)
    gr =pa.creategroupingrelationship(type='same malware family',malware_toolkit_name='Test malware toolkit',malware_family_name='Tes malware family name',clustering_metadata=cm)
    pa.add_grouping_relationship(grouping_relationship=gr)
    ####################################################################################################################
    #Printing results
    print(pa.to_xml())


from maec.bundle import Bundle,AVClassification,ProcessTree,ProcessTreeNode,Capability,CapabilityProperty,CapabilityObjective,CapabilityObjectiveReference,CapabilityObjectiveRelationship, \
    CapabilityReference,CapabilityRelationship

from maec.bundle.behavior_reference import BehaviorReference
from mixbox.idgen import set_id_method,set_id_namespace,IDGenerator
from cybox.core import ActionReference
from cybox.objects.process_object import ChildPIDList,ArgumentList,PortList,NetworkConnectionList
from cybox.common import EnvironmentVariableList, Duration,DateTime,ExtractedFeatures
from cybox.objects.port_object import Port
from cybox.objects.network_connection_object import NetworkConnection

class MaecBundle(Bundle):

    def __init__(self,id =None,namespace=None,defined_subject=None,schema_version="4.1",content_type=None,timestamp=None,malware_instance_object=None):
        if namespace is not None:
            set_id_method(IDGenerator.METHOD_UUID)
            set_id_namespace(namespace)
        super(MaecBundle,self).__init__(id =id,defined_subject=defined_subject,schema_version=schema_version,content_type=content_type,malware_instance_object=malware_instance_object)
        self.timestamp = timestamp

    def add_content_type(self,content_type):
        self.content_type =content_type

    def add_malware_instance_object_attribute(self,malware_instance_object=None):
        self.set_malware_instance_object_attributes(malware_instance_object=malware_instance_object)

    def create_av_classification(self,classification=None,tool_name=None,engine_version=None,definition_version=None,tool_vendor=None):
        av_classification =  AVClassification(classification=classification,tool_name=tool_name,tool_vendor=tool_vendor)
        av_classification.engine_version = engine_version
        av_classification.definition_version =definition_version
        return av_classification

    def add_process_tree(self,process_tree):
        self.set_process_tree(process_tree=process_tree)

    def create_process_tree(self,root_process):
        return ProcessTree(root_process=root_process)


    def create_process_tree_node(self,id=None,parent_action_idref=None,spawned_processes=None,ordinal_position=None,injected_processes=None,initiated_actions=None,pid=None,name=None,
                                 creation_time=None,image_info=None,argument_list=None,environment_variable_list=None,kernel_time=None,port_list=None,network_connection_list=None,
                                 start_time=None,username=None,user_time=None,extracted_features=None):
        process_tree_node =ProcessTreeNode(id=id,parent_action_idref=parent_action_idref)
        process_tree_node.pid =pid
        process_tree_node.ordinal_position = ordinal_position
        process_tree_node.name =name
        process_tree_node.username =username
        if extracted_features is not None and isinstance(extracted_features,ExtractedFeatures):
            process_tree_node.extracted_features =extracted_features
        if user_time is not None:
            process_tree_node.user_time = Duration(user_time)
        if creation_time is not None:
            process_tree_node.creation_time =DateTime(creation_time)
        process_tree_node.image_info =image_info
        if kernel_time is not None:
            process_tree_node.kernel_time = Duration(kernel_time)
        if start_time is not None:
            process_tree_node.start_time = DateTime(start_time)
        if network_connection_list is not None:
            process_tree_node.network_connection_list = NetworkConnectionList()
            for connection in network_connection_list:
                if isinstance(connection,NetworkConnection):
                    process_tree_node.network_connection_list.append(connection)
        if port_list is not None:
            process_tree_node.port_list = PortList()
            for port in port_list:
                if isinstance(port,Port):
                    process_tree_node.port_list.append(port)
        if environment_variable_list is not None:
            process_tree_node.environment_variable_list = EnvironmentVariableList()
            for variable in environment_variable_list:
                process_tree_node.environment_variable_list.append(variable)
        if argument_list is not None:
            process_tree_node.argument_list = ArgumentList()
            for argument in argument_list:
                process_tree_node.argument_list.append(argument)
        if spawned_processes is not None:
            process_tree_node.child_pid_list = ChildPIDList()
            for process in spawned_processes:
                if isinstance(process,ProcessTreeNode):
                    process.parent_pid =process_tree_node.pid
                    process_tree_node.add_spawned_process(process_node=process)
                    process_tree_node.child_pid_list.append(process.pid)
        if injected_processes is not None:
            for process in injected_processes:
                if isinstance(process,ProcessTreeNode):
                    process_tree_node.add_injected_process(process_node=process)
        if initiated_actions is not None:
            for action in initiated_actions:
                if isinstance(action,ActionReference):
                    process_tree_node.add_initiated_action(action)
        return process_tree_node

    def create_capability(self,id=None,name=None,description=None,properties=None,strategic_objectives=None,tactical_objectives=None,behavior_reference=None,relationship=None):
        capability = Capability(id=id,name=name)
        capability.description = description
        capability.property =properties
        if strategic_objectives is not None:
            capability.strategic_objective = []
            for strategic_objective in strategic_objectives:
                if isinstance(strategic_objective,CapabilityObjective):
                    capability.strategic_objective.append(strategic_objective)
        if tactical_objectives is not None:
            capability.tactical_objective = []
            for tactical_objective in tactical_objectives:
                if isinstance(tactical_objective,CapabilityObjective):
                    capability.tactical_objective.append(tactical_objective)
        capability.behavior_reference =behavior_reference
        capability.relationship = relationship
        return capability

    def create_capability_property(self,name=None,value=None):
        property = CapabilityProperty()
        property.name = name
        property.value = value
        return property

    def create_capability_relationship(self,capability_reference=None,relationship_type=None):
        relationship = CapabilityRelationship()
        for reference in capability_reference:
            relationship.capability_reference.append(reference)
        relationship.relationship_type = relationship_type
        return relationship

    def create_capability_reference(self,capability_idref=None):
        capability_reference =  CapabilityReference()
        capability_reference.capability_idref = capability_idref
        return capability_reference

    def create_capability_objective(self,id=None,name=None,description=None,properties=None,behavior_references=None,relationship=None):
        objective = CapabilityObjective(id=id)
        objective.name = name
        objective.description = description
        objective.property = properties
        objective.behavior_reference = behavior_references
        objective.relationship = relationship
        return objective

    def create_capability_objective_relationship(self,objective_reference=None,relationship_type=None):
        relationship = CapabilityObjectiveRelationship()
        for reference in objective_reference:
            relationship.objective_reference.append(reference)
        relationship.relationship_type = relationship_type
        return relationship

    def create_capability_objective_reference(self,objective_idref=None):
        objective_reference =  CapabilityObjectiveReference()
        objective_reference.objective_idref =objective_idref
        return objective_reference

    def create_behavior_reference(self,behavior_idref=None):
        return BehaviorReference(behavior_idref=behavior_idref)

if __name__ =='__main__':
    #Testing example
    from mixbox.namespaces import Namespace
    import datetime
    mb = MaecBundle(namespace=Namespace('testnamespace','totest','testschemalocation'),timestamp=datetime.datetime.now(),defined_subject=True)
    ####################################################################################################################
    #Add content type
    mb.add_content_type(content_type='dynamic analysis tool output')
    #Add malware instance object attribute
    ####################################################################################################################
    from maec_ioc_processor.cybox.cybox_object import CyboxObject
    co = CyboxObject()
    co.objecttype.file_name='Test filename'
    mb.add_malware_instance_object_attribute(malware_instance_object=co.objecttype)
    ####################################################################################################################
    #Add AV Classifications
    av_classification1=mb.create_av_classification(classification='Test classification name',tool_name='Test tool name',engine_version='2.1.ev',definition_version='2.1.dv',tool_vendor='Avira')
    av_classification2=mb.create_av_classification(classification='Test classification name',tool_name='Test tool name',engine_version='2.1.ev',definition_version='2.1.dv',tool_vendor='Norton')
    mb.add_av_classification(av_classification=av_classification1)
    mb.add_av_classification(av_classification=av_classification2)
    ####################################################################################################################
    #Add process tree
    ar1 = ActionReference(action_id='Test action id 1')
    ar2 = ActionReference(action_id='Test action id 2')
    ar3 = ActionReference(action_id='Test action id 3')
    ar4 = ActionReference(action_id='Test action id 4')
    node1 = mb.create_process_tree_node(pid=1111,ordinal_position=2,initiated_actions=[ar3,ar4])
    node2 = mb.create_process_tree_node(pid=2222,ordinal_position=3)
    node3 = mb.create_process_tree_node(pid=3333,ordinal_position=4)
    node4 = mb.create_process_tree_node(pid=4444,ordinal_position=5)
    root_process = mb.create_process_tree_node(pid =1234,parent_action_idref='Test parent action idref',ordinal_position=1,spawned_processes=[node1,node2],injected_processes=[node3,node4],
                                               initiated_actions=[ar1,ar2],name='Test process name',creation_time=datetime.datetime.now(),argument_list=['Arg1','Arg2'],kernel_time=10000,
                                               start_time=datetime.datetime.now(),user_time=datetime.datetime.now())
    tree = mb.create_process_tree(root_process=root_process)
    mb.add_process_tree(process_tree=tree)
    ####################################################################################################################
    #Add capability
    prop1 = mb.create_capability_property(name='Test property name 1',value='test property value 1')
    prop2 = mb.create_capability_property(name='Test property name 2',value='test property value 2')
    prop3 = mb.create_capability_property(name='Test property name 3',value='test property value 3')
    prop4 = mb.create_capability_property(name='Test property name 4',value='test property value 4')
    prop5 = mb.create_capability_property(name='Test property name 5',value='test property value 5')
    prop6 = mb.create_capability_property(name='Test property name 6',value='test property value 6')
    bref1= mb.create_behavior_reference(behavior_idref='Test behavior ref 1')
    bref2= mb.create_behavior_reference(behavior_idref='Test behavior ref 2')
    objref1  = mb.create_capability_objective_reference(objective_idref='Test capability objective reference 1')
    objref2  = mb.create_capability_objective_reference(objective_idref='Test capability objective reference 2')
    objrelationship = mb.create_capability_objective_relationship(objective_reference=[objref1,objref2],relationship_type='Tactical')
    objective1 = mb.create_capability_objective(name='Test tactical objective name',description='Tactical objective description',properties=[prop3,prop4],behavior_references=bref1,
                                                relationship=objrelationship)
    objective2 = mb.create_capability_objective(name='Test strategic objective name',description='Strategic objective description',properties=[prop5,prop6],behavior_references=bref2)
    bref3= mb.create_behavior_reference(behavior_idref='Test behavior ref 3')
    bref4= mb.create_behavior_reference(behavior_idref='Test behavior ref 4')
    capref1  = mb.create_capability_reference(capability_idref='Test capability reference 1')
    capref2  = mb.create_capability_reference(capability_idref='Test capability  reference 2')
    caprelationship = mb.create_capability_relationship(capability_reference=[capref1,capref2],relationship_type='Strategic')
    capability = mb.create_capability(name="Test capability name",properties=[prop1,prop2],strategic_objectives=[objective2],tactical_objectives=[objective1],behavior_reference=[bref3,bref4],
                                      relationship=caprelationship)
    mb.add_capability(capability=capability)
    ####################################################################################################################
    #Add behavior
    ####################################################################################################################
    #Printing results
    print(mb.to_xml())
    #print(capability.to_xml())
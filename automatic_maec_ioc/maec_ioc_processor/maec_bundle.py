from maec.bundle import Bundle,AVClassification,ProcessTree,ProcessTreeNode,Capability,CapabilityProperty,CapabilityObjective,CapabilityObjectiveReference,CapabilityObjectiveRelationship, \
    CapabilityReference,CapabilityRelationship,AssociatedCode,BehaviorCollection,ObjectCollection,ActionCollection,Collections,ActionCollectionList,BehaviorCollectionList,ObjectCollectionList, \
    CandidateIndicatorCollectionList,CandidateIndicatorCollection
from maec.bundle.behavior_reference import BehaviorReference
from maec.bundle.behavior import Behavior,BehaviorPurpose,Exploit,CVEVulnerability,PlatformList,BehavioralActions,BehavioralAction,BehavioralActionEquivalenceReference,BehavioralActionReference
from mixbox.idgen import set_id_method,set_id_namespace,IDGenerator
from cybox.core import ActionReference
from cybox.objects.process_object import ChildPIDList,ArgumentList,PortList,NetworkConnectionList
from cybox.common import EnvironmentVariableList, Duration,DateTime
from cybox.common.extracted_features import ExtractedFeatures,Imports,Functions,ExtractedStrings,CodeSnippets
from cybox.common.extracted_string import ExtractedString
from cybox.objects.port_object import Port
from cybox.objects.network_connection_object import NetworkConnection
from cybox.common.platform_specification import PlatformIdentifier,PlatformSpecification
from cybox.common.structured_text import StructuredText
from cybox.objects.code_object import Code,TargetedPlatforms,CodeSegmentXOR
from cybox.common.digitalsignature import DigitalSignature,DigitalSignatureList
from maec.bundle.candidate_indicator import CandidateIndicator,MalwareEntity,CandidateIndicatorComposition
from maec.bundle.object_reference import ObjectReference

from maec_bundle_action import MaecBundleAction
from maec_ioc_processor.cybox.cybox_object import CyboxObject

class MaecBundle(Bundle):

    def __init__(self,id =None,namespace=None,defined_subject=None,schema_version="4.1",content_type=None,timestamp=None,malware_instance_object=None):
        if namespace is not None:
            set_id_method(IDGenerator.METHOD_UUID)
            set_id_namespace(namespace)
        super(MaecBundle,self).__init__(id =id,defined_subject=defined_subject,schema_version=schema_version,content_type=content_type,malware_instance_object=malware_instance_object)
        self.timestamp = timestamp
        self.collections = Collections()
        self.collections.action_collections = ActionCollectionList()
        self.collections.behavior_collections = BehaviorCollectionList()
        self.collections.object_collections = ObjectCollectionList()
        self.collections.candidate_indicator_collections = CandidateIndicatorCollectionList()

    def create_candidate_indicator(self,id=None,creation_datetime=None,lastupdate_datetime=None,version=None, importance=None,numeric_importance=None,author=None,description=None,
                                   malware_entity=None,composition=None):
        candidate_indicator = CandidateIndicator(id=id)
        candidate_indicator.creation_datetime = creation_datetime
        candidate_indicator.lastupdate_datetime = lastupdate_datetime
        candidate_indicator.version = version
        candidate_indicator.importance =importance
        candidate_indicator.numeric_importance = numeric_importance
        candidate_indicator.author = author
        candidate_indicator.description = description
        candidate_indicator.malware_entity = malware_entity
        candidate_indicator.composition = composition
        return candidate_indicator

    def create_candidate_indicator_malware_entity(self,type=None,name=None,description=None):
        malware_entity = MalwareEntity()
        malware_entity.type_ = type
        malware_entity.name =name
        malware_entity.description = description
        return malware_entity

    def create_candidate_indicator_composition(self,action_reference_list=None,behavior_reference_list=None,object_reference_list=None,sub_composition=None):
        composition = CandidateIndicatorComposition()
        if action_reference_list is not None:
            composition.action_reference =[]
            for reference in action_reference_list:
                composition.action_reference.append(ActionReference(action_id=reference))
        if behavior_reference_list is not None:
            composition.behavior_reference =[]
            for reference in behavior_reference_list:
                composition.behavior_reference.append(BehaviorReference(behavior_idref=reference))
        if object_reference_list is not None:
            composition.object_reference=[]
            for reference in object_reference_list:
                composition.object_reference.append(ObjectReference(object_idref=reference))
        composition.sub_composition = sub_composition
        return composition

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

    def create_behavior(self,id=None,description=None,ordinal_position=None,status=None,duration=None,behavior_purpose=None,discovery_method=None,action=None,action_equivalence_reference=None,
                        action_reference=None,associated_code=None):
        behavior = Behavior(id=id,description=description)
        behavior.ordinal_position = ordinal_position
        behavior.status = status
        behavior.duration = duration
        if isinstance(behavior_purpose,BehaviorPurpose):
            behavior.purpose = behavior_purpose
        behavior.discovery_method = discovery_method
        if action is not None or action_equivalence_reference is not None or action_reference is not None:
            behavior.action_composition= BehavioralActions()
            behavior.action_composition.action= action
            behavior.action_composition.action_reference= action_reference
            behavior.action_composition.action_equivalence_reference = action_equivalence_reference
        if associated_code is not None:
            behavior.associated_code = AssociatedCode()
            for code in associated_code:
                if isinstance(code,Code):
                    behavior.associated_code.append(code)
        return behavior

    def create_behavior_associated_code(self,type=None,description=None,purpose=None,code_language=None,targeted_platforms=None,processor_family=None,discovery_method=None,
                                        start_address=None,code_segment=None,code_segment_xor=None,xor_pattern=None,digital_signatures=None,extracted_features=None):
        code = Code()
        code.type_ =type
        code.description = StructuredText(description)
        code.purpose = purpose
        code.code_language = code_language
        if targeted_platforms is not None:
            code.targeted_platforms =TargetedPlatforms()
            for platform in targeted_platforms:
                code.targeted_platforms.append(platform)
        code.processor_family = processor_family
        code.discovery_method =discovery_method
        code.start_address = start_address
        code.code_segment = code_segment
        if code_segment_xor is not None:
            code.code_segment_xor = CodeSegmentXOR(value=code_segment_xor)
            code.code_segment_xor.xor_pattern= xor_pattern
        if digital_signatures is not None:
            code.digital_signatures = DigitalSignatureList()
            for signature in digital_signatures:
                code.digital_signatures.append(signature)
        code.extracted_features = extracted_features
        return code

    def create_behavior_associated_code_digital_signature(self,signature_verified=None,signature_exists=None,certificate_subject=None,certificate_issuer=None,
                                                          signature_description=None):
        signature = DigitalSignature()
        signature.signature_verified = signature_verified
        signature.signature_exists = signature_exists
        signature.certificate_subject = certificate_subject
        signature.certificate_issuer = certificate_issuer
        signature.signature_description = signature_description
        return signature

    def create_behavior_associated_code_extracted_feautures(self,functions=None,imports=None,codesnippets=None,extractedstrings=None):
        extft = ExtractedFeatures()
        if functions is not None and (all(isinstance(x,str ) for x in functions)):
            extft.functions = Functions()
            for func in functions:
                extft.functions.append(func)

        if imports is not None and (all(isinstance(x,str ) for x in imports)):
            extft.imports = Imports()
            for imp in imports:
                extft.imports.append(imp)

        if codesnippets is not None and (all(isinstance(x,str ) for x in codesnippets)):
            extft.code_snippets = CodeSnippets()
            for codsn in codesnippets:
                code = Code()
                code.code_segment=codsn
                extft.code_snippets.append(code)

        if extractedstrings is not None and (all(isinstance(x,str ) for x in extractedstrings)):
            extft.strings = ExtractedStrings()
            for exstr in extractedstrings:
                extracted_string = ExtractedString(string_value=exstr)
                extft.strings.append(extracted_string)
        return extft

    def create_behavior_action(self,behavioral_ordering):
        action = BehavioralAction()
        action.behavioral_ordering = behavioral_ordering
        return action

    def create_behavior_action_reference(self,action_id=None,behavioral_ordering=None):
        action_reference = BehavioralActionReference()
        action_reference.behavioral_ordering = behavioral_ordering
        action_reference.action_id = action_id
        return action_reference

    def create_behavior_action_equivalence_reference(self,behavioral_ordering,action_equivalence_idref):
        action_equivalence_reference = BehavioralActionEquivalenceReference()
        action_equivalence_reference.behavioral_ordering = behavioral_ordering
        action_equivalence_reference.action_equivalence_idref = action_equivalence_idref
        return action_equivalence_reference

    def create_behavior_purpose(self,description=None,known_vulnerability=None,cve_description=None,cve_id=None,cwe_id=None,targeted_platforms=None):
        cve = CVEVulnerability()
        cve.description = cve_description
        cve.cve_id = cve_id
        vulnerability_exploit=Exploit()
        vulnerability_exploit.known_vulnerability = known_vulnerability
        vulnerability_exploit.cve = cve
        vulnerability_exploit.cwe_id =cwe_id
        if targeted_platforms is not None:
            vulnerability_exploit.targeted_platforms = PlatformList()
            for platform in targeted_platforms:
                vulnerability_exploit.targeted_platforms.append(platform)
        behavior_purpose = BehaviorPurpose()
        behavior_purpose.description = description
        behavior_purpose.vulnerability_exploit=vulnerability_exploit
        return behavior_purpose

    def create_behavior_targeted_platform(self,description=None,identifiers=None):
        platform = PlatformSpecification()
        if description is not None:
            platform.description= StructuredText(value=description)
        if not identifiers is None:
            for identifier in identifiers:
                platform.identifiers.append(identifier)
        return platform

    def create_behavior_targeted_platform_identifier(self,system=None,system_ref =None):
        identifier = PlatformIdentifier()
        identifier.system =system
        identifier.system_ref =system_ref
        return identifier

    def create_behavior_collection(self,id= None,name=None,affinity_degree=None,affinity_type=None,description=None,behavior_list=None):
        collection =  BehaviorCollection(id=id,name=name)
        collection.affinity_degree=affinity_degree
        collection.description = description
        collection.affinity_type = affinity_type
        for behavior in behavior_list:
            if isinstance(behavior,Behavior):
                collection.add_behavior(behavior)
        return collection

    def add_named_behavior_collection_1(self,behavior_collection):
        self.collections.behavior_collections.append(behavior_collection)

    def create_action_collection(self,id= None,name=None,affinity_degree=None,affinity_type=None,description=None,action_list=None):
        collection =  ActionCollection(id=id,name=name)
        collection.affinity_degree=affinity_degree
        collection.description = description
        collection.affinity_type = affinity_type
        for action in action_list:
            if isinstance(action,MaecBundleAction):
                collection.add_action(action)
        return collection

    def add_named_action_collection_1(self,action_collection):
        self.collections.action_collections.append(action_collection)

    def create_object_collection(self,id= None,name=None,affinity_degree=None,affinity_type=None,description=None,object_list=None):
        collection =  ObjectCollection(id=id,name=name)
        collection.affinity_degree=affinity_degree
        collection.description = description
        collection.affinity_type = affinity_type
        for object in object_list:
            if isinstance(object,CyboxObject):
                collection.add_object(object.objecttype)
        return collection

    def add_named_object_collection_1(self,object_collection):
        self.collections.object_collections.append(object_collection)

    def create_candidate_indicator_collection(self,id= None,name=None,affinity_degree=None,affinity_type=None,description=None,candidate_indicator_list=None):
        collection =  CandidateIndicatorCollection(id=id,name=name)
        collection.affinity_degree=affinity_degree
        collection.description = description
        collection.affinity_type = affinity_type
        for candidate_indicator in candidate_indicator_list:
            if isinstance(candidate_indicator,CandidateIndicator):
                collection.add_candidate_indicator(candidate_indicator)
        return collection

    def add_named_candidate_indicator_collection_1(self,candidate_indicator_collection):
        self.collections.candidate_indicator_collections.append(candidate_indicator_collection)


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
                                               start_time=datetime.datetime.now(),user_time=datetime.datetime.now(),extracted_features=None)
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
    ident1 = mb.create_behavior_targeted_platform_identifier(system='win',system_ref='Test system ref 2')
    platform1 = mb.create_behavior_targeted_platform(description='Platform 1',identifiers=[ident1])
    ident2 = mb.create_behavior_targeted_platform_identifier(system='unix',system_ref='Test system ref 2')
    platform2 = mb.create_behavior_targeted_platform(description='Platform 2',identifiers=[ident2])
    purpose = mb.create_behavior_purpose(description='Test  purpose description',known_vulnerability='true',cve_description='CVE test description',cve_id='12345',cwe_id=[12,34,56],
                                         targeted_platforms=[platform1,platform2])
    action=mb.create_behavior_action(behavioral_ordering=1)
    action_reference= mb.create_behavior_action_reference(behavioral_ordering=2,action_id='Test action id 1')
    action_equivalence_reference= mb.create_behavior_action_equivalence_reference(behavioral_ordering=3,action_equivalence_idref='equiv idref 1')
    from maec_ioc_processor.cybox_discovery_method import CyboxDiscoveryMethod
    dm = CyboxDiscoveryMethod()
    dm.add_discovery_method_name(name='Test behavior discovey method name')
    extrfeat1 = mb.create_behavior_associated_code_extracted_feautures(functions=['extr feaut fun 1'],imports=['extr feat imp 1'],codesnippets=['code1 snip'],extractedstrings=['extstring 1'])
    digsign1 = mb.create_behavior_associated_code_digital_signature(signature_description='Test signature description 1',signature_exists=True,signature_verified=True,certificate_subject='Test certificate subject 1')
    digsign2 = mb.create_behavior_associated_code_digital_signature(signature_description='Test signature description 2',signature_exists=True,signature_verified=True,certificate_subject='Test certificate subject 2')
    ident3 = mb.create_behavior_targeted_platform_identifier(system='win',system_ref='Test system ref 3')
    platform3 = mb.create_behavior_targeted_platform(description='Platform 3',identifiers=[ident3])
    dm1 = CyboxDiscoveryMethod()
    dm1.add_discovery_method_name(name = 'Code discovey method')
    code = mb.create_behavior_associated_code(type='Test type code',description='Test description',purpose='Test code purpose',code_language='Test code language',
                                              targeted_platforms=[platform3],processor_family=['amd','i386'],discovery_method=dm1,start_address=hex(12355),code_segment='Test code segment',
                                              code_segment_xor='Test xor segment',xor_pattern=hex(11111),digital_signatures=[digsign1,digsign2],extracted_features=extrfeat1)

    behavior = mb.create_behavior(description='Test behavior description',ordinal_position=3,status='Success',duration=10000,behavior_purpose=purpose,discovery_method=dm,action=action,
                                  action_reference=action_reference, action_equivalence_reference=action_equivalence_reference,associated_code=[code])
    mb.add_behavior(behavior=behavior)
    ####################################################################################################################
    #Add action
    act = MaecBundleAction()
    act.add_action_name('Create Hidden File')
    mb.add_action(action=act)
    ####################################################################################################################
    #Add object
    obj = CyboxObject()
    obj.objecttype.file_name='Test obj name'
    mb.add_object(object=obj.objecttype)
    ####################################################################################################################
    #Add candidate indicator
    comp = mb.create_candidate_indicator_composition(action_reference_list=['ar11','ar22'],behavior_reference_list=['br11','br22'],object_reference_list=['or11','or22'])
    composition = mb.create_candidate_indicator_composition(action_reference_list=['ar1','ar2','ar3'],behavior_reference_list=['br1','br2','br3'],object_reference_list=['or1','or2','or3'],
                                                            sub_composition=comp)
    mal_ent = mb.create_candidate_indicator_malware_entity(type='family',name='Malware entity test name',description='Malware entity description')
    can_ind = mb.create_candidate_indicator(creation_datetime=datetime.datetime.now(),lastupdate_datetime=datetime.datetime.now(),version='2.1',importance='high',numeric_importance=5,
                                            author='Test author',description="Test candidate indicator description",malware_entity=mal_ent,composition=composition)
    mb.add_candidate_indicator(candidate_indicator=can_ind)
    ####################################################################################################################
    #Add collections
    #Add named behavior collection 1st way
    beh1 = mb.create_behavior(description='Test behavior collection description 1',ordinal_position=1,status='Success')
    beh2 = mb.create_behavior(description='Test behavior collection description 2',ordinal_position=2,status='Success')
    beh_collection =  mb.create_behavior_collection(name='Test collection name 1',affinity_degree='high',affinity_type='Test affinity type',
                                                    description='Test behavior collection descr',behavior_list=[beh1,beh2])
    mb.add_named_behavior_collection_1(behavior_collection=beh_collection)
    #Add named behavior collection 2nd way.bug in library
    #testname='Test collection name 2'
    #mb.add_named_behavior_collection(collection_name=testname)
    #mb.add_behavior(behavior=beh1,behavior_collection_name=testname)
    #Add named action collection 1st way
    act1 = MaecBundleAction()
    act1.add_action_name('Create Hidden File')
    act2 = MaecBundleAction()
    act2.add_action_name('Create Hidden File')
    act_collection =  mb.create_action_collection(name='Test collection act name 1',affinity_degree='high',affinity_type='Test affinity type',
                                                    description='Test action collection descr',action_list=[act1,act2])
    mb.add_named_action_collection_1(act_collection)
    #Add named action collection 2nd way
    testname='Test action collection name 2'
    mb.add_named_action_collection(testname)
    mb.add_action(action=act1,action_collection_name=testname)
    #Add named object collection 1st way
    obj1 = CyboxObject()
    obj1.objecttype.file_name='Test obj1 name'
    obj2 = CyboxObject()
    obj2.objecttype.file_name='Test obj2 name'
    obj_collection =  mb.create_object_collection(name='Test collection obj name 1',affinity_degree='high',affinity_type='Test affinity type',
                                                    description='Test object collection descr',object_list=[obj1,obj2])
    mb.add_named_object_collection_1(obj_collection)
    #Add named object collection 2nd way
    testname='Test object collection name 2'
    mb.add_named_object_collection(testname)
    mb.add_object(object=obj1.objecttype,object_collection_name=testname)
    #Add named candidate indicator collection 1st way
    can_ind1 = mb.create_candidate_indicator(author='Test author 1')
    can_ind2 = mb.create_candidate_indicator(author='Test author 2')
    can_ind_collection = mb.create_candidate_indicator_collection(name='Test collection can ind name 1',affinity_degree='high',affinity_type='Test affinity type',
                                                    description='Test can ind collection descr',candidate_indicator_list=[can_ind1,can_ind2])
    mb.add_named_candidate_indicator_collection_1(can_ind_collection)
    #Add named candidate indicator collection 2nd way.bug in library
    #testname='Test can ind collection name 2'
    #mb.add_named_candidate_indicator_collection(testname)
    #mb.add_candidate_indicator(candidate_indicator=can_ind1,candidate_indicator_collection_name=testname)

    #Printing results
    print(mb.to_xml())
    #print(capability.to_xml())
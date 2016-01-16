from apt_pkg import md5sum

__author__ = 'george'

from cybox.core import Action, ActionArguments, ActionArgument,ActionAliases,Frequency, AssociatedObjects, AssociatedObject,ActionRelationships, ActionRelationship, ActionReference
from mixbox.idgen import IDGenerator, set_id_method, set_id_namespace, create_id

class CyboxAction(Action):
    def __init__(self, id=None, idref=None, namespace=None,name=None,action_status=None,context=None,description=None,discovery_method=None,frequency=None,action_aliases=None,
                 action_arguments=None,ordinal_position=None,timestamp=None,type=None,associated_objects=None,relationships=None
                 ):
        super(CyboxAction, self).__init__()
        set_id_method(IDGenerator.METHOD_UUID)
        if id is None and idref is None:
            if namespace is not None:
                set_id_namespace(namespace)
            self.id_ = create_id(prefix='action')
        self.action_arguments = action_arguments
        self.action_aliases = action_aliases
        self.discovery_method = discovery_method
        self.name = name
        self.action_status = action_status
        self.associated_objects = associated_objects
        self.type_ = type
        self.timestamp = timestamp
        self.relationships =relationships
        self.ordinal_position = ordinal_position
        self.frequency= frequency
        self.description = description
        self.context = context

    def add_relationships(self,action_relationship):
        if not isinstance(self.relationships,ActionRelationships):
            self.relationships = ActionRelationships()
        self.relationships.append(action_relationship)

    def create_action_relationship(self,type=None,action_references=None):
        actionrelationship = ActionRelationship()
        actionrelationship.type =type
        if action_references is not None:
            for actionref in action_references:
                actionrelationship.action_references.append(actionref)
        return  actionrelationship

    def create_action_reference(self,action_id=None):
        return  ActionReference(action_id=action_id)

    def add_associated_objects(self,associated_object):
        if not isinstance(self.associated_objects,AssociatedObjects):
            self.associated_objects = AssociatedObjects()
        self.associated_objects.append(associated_object)

    def create_associated_object(self,defined_object=None,association_type=None,type=None):
        return AssociatedObject(defined_object=defined_object,association_type=association_type)

    def add_type(self,type):
        self.type_ = type

    def add_timestamp(self,timestamp):
        self.timestamp=timestamp

    def add_ordinal_position(self,ordinal_position):
        self.ordinal_position=ordinal_position

    def add_frequnecy(self,rate=None,scale=None,trend=None,units=None):
        self.frequency= Frequency()
        self.frequency.rate =rate
        self.frequency.scale=scale
        self.frequency.trend=trend
        self.frequency.units=units


    def add_description(self,description):
        self.description =description

    def add_context(self,context):
        self.context =context

    def add_action_status(self,action_status):
        self.action_status =action_status

    def add_action_name(self,name):
        self.name=name

    def add_action_argument(self, action_argument):
        if not isinstance(self.action_arguments,ActionArguments):
            self.action_arguments = ActionArguments()
        self.action_arguments.append(action_argument)

    def create_action_argument(self, name, value):
        '''
        Is optional and enables the specification of a single relevant argument/parameter for this Action.
        Name must be taken from cybox.vocabs.ActionArgumentNameEnum
        '''
        action_argument = ActionArgument()
        action_argument.argument_name = name
        action_argument.argument_value = value
        return action_argument

    def add_action_alias(self,action_alias):
        '''
        Adds action_alias names, enabling identification of other potentially used names for this Action.
        '''
        if not isinstance(self.action_aliases,ActionAliases):
            self.action_aliases = ActionAliases()
        self.action_aliases.append(action_alias)

    def add_location(self):
        '''
        future implementation
        :return:
        '''
        pass

    def add_discovery_method(self,discovery_method):
        self.discovery_method = discovery_method


if __name__ == '__main__':
    ex = CyboxAction()
    #Add Action Type
    ex.add_type('Access')
    ###################################################################################################################
    #Add Action Name
    ex.add_action_name('Accept Socket Connection')
    ###################################################################################################################
    #Add Action Description
    ex.add_description('Example description')
    ###################################################################################################################
    #Add Action Alias
    ex.add_action_alias('Add Network Share')
    ex.add_action_alias('Add System Call Hook')
    ###################################################################################################################
    #Add Action Argument
    ex.add_action_argument(ex.create_action_argument(name='API',value='test'))
    ###################################################################################################################
    #Add Action Location
    #ex.addlocation()
    ###################################################################################################################
    #Add Discovery Method
    from cybox_discovery_method import CyboxDiscoveryMethod
    dm = CyboxDiscoveryMethod()
    dm.add_discovery_method_name(name='Test discovey method name')
    ex.add_discovery_method(discovery_method=dm)
    ###################################################################################################################
    #Add Action Status
    ex.add_action_status(action_status='Success')
    ###################################################################################################################
    #Add Action Context
    ex.add_context(context='Host')
    ###################################################################################################################
    #Add timestamp
    import datetime
    ex.add_timestamp(timestamp=datetime.datetime.now())
    ###################################################################################################################
    #Add Ordinal Position
    ex.add_ordinal_position(15)
    ###################################################################################################################
    #Add Associated objects
    from cybox.objects.product_object import Product
    from cybox.common.vocabs import ActionObjectAssociationType
    at = ActionObjectAssociationType()
    at.value = ActionObjectAssociationType.TERM_AFFECTED
    dobj = Product()
    dobj.product='TestProduct'
    ob1 = ex.create_associated_object(defined_object=dobj,association_type=at)
    ex.add_associated_objects(associated_object=ob1)
    ###################################################################################################################
    # Add Frequency
    ex.add_frequnecy(rate=15,scale=18,trend=7,units=19)
    ###################################################################################################################
    # Add Relationships
    from cybox.common.vocabs import ActionRelationshipType
    ar= ActionRelationship()
    ar.value = ActionRelationshipType.TERM_INITIATED
    rf1 = ex.create_action_reference(action_id='test1d:1234')
    rel1 = ex.create_action_relationship(action_references=[rf1],type=ar)
    ex.add_relationships(action_relationship=rel1)
    ###################################################################################################################
    #Printing results
    print(ex.to_xml())

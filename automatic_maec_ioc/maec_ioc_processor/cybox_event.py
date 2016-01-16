__author__ = 'george'
from mixbox.idgen import IDGenerator, set_id_method,set_id_namespace,create_id
from cybox.core import Event,Actions, ActionRelationship, Frequency

from maec_ioc_processor.cybox_action import CyboxAction


class CyboxEvent(Event):

    def __init__(self, id=None, idref=None, namespace=None,type=None,observation_method=None,frequency=None,event=None,description=None):
        super(CyboxEvent,self).__init__()
        set_id_method(IDGenerator.METHOD_UUID)
        if id is None and idref is None:
            if namespace is not None:
                set_id_namespace(namespace)
            self.id_ = create_id(prefix='event')
        self.actions = Actions()
        self.type_= type
        self.observation_method = observation_method
        self.idref =idref
        self.frequency = frequency
        self.event =[]
        if isinstance(event,CyboxEvent):
            self.event.append(event)
        self.description =description
        self._namespace =namespace

    def add_event(self,event):
        if isinstance(event,CyboxEvent):
            self.event.append(event)

    def add_frequnecy(self,rate=None,scale=None,trend=None,units=None):
        self.frequency= Frequency()
        self.frequency.rate =rate
        self.frequency.scale=scale
        self.frequency.trend=trend
        self.frequency.units=units

    def add_type(self,type):
        self.type_=type

    def add_description(self,description):
        self.description =description

    def add_action(self,action):
        if isinstance(action,CyboxAction ):
            self.actions.append(action)

    def add_observation_method(self,observation_method):
        self.observation_method = observation_method

if __name__=='__main__':
    ex1 = CyboxEvent()
    #Creating CyboxAction
    ###################################################################################################################
    ###################################################################################################################
    ###################################################################################################################
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
    #Add discovery Method
    from cybox_discovery_method import CyboxDiscoveryMethod
    dm = CyboxDiscoveryMethod()
    dm.add_discovery_method_name('Test discovery name')
    ex.add_discovery_method(dm)
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
    ###################################################################################################################
    ###################################################################################################################
    #print(ex.to_xml())
    #Add actions in event
    ex1.add_action(ex)
    #Add Observation Method in event
    om = CyboxDiscoveryMethod()
    om.add_discovery_method_name('Test obsrervation name')
    ex1.add_observation_method(om)
    ###################################################################################################################
    #Add type in event
    ex1.add_type(type='Registry Ops')
    ###################################################################################################################
    #Add description
    ex1.add_description('Event example description')
    ###################################################################################################################
    #Add frequency
    ex1.add_frequnecy(rate=15,scale=18,trend=7,units=19)
    ###################################################################################################################
    #Add event
    ex2 = CyboxEvent(description='Example event2 description')
    ex1.add_event(ex2)
    #Printing results
    print(ex1.to_xml())

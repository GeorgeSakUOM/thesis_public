__author__ = 'george'

from maec.bundle.malware_action import MalwareAction,ActionImplementation,APICall,Parameter,ParameterList
from cybox.objects.code_object import CodeSegmentXOR,Code,TargetedPlatforms
from cybox.common.structured_text import StructuredText
from  cybox.common.digitalsignature import DigitalSignature,DigitalSignatureList
from cybox.common.extracted_features import ExtractedFeatures,ExtractedStrings,CodeSnippets,Imports,Functions
from cybox.common.extracted_string import ExtractedString
from cybox.common.platform_specification import PlatformSpecification,PlatformIdentifier

from maec_ioc_processor.cybox.cybox_action import CyboxAction


class MaecBundleAction(CyboxAction,MalwareAction):

    def __init__(self,idref=None,namespace=None,implementation_id=None,implementation_code =None,implementation_api_call=None,implementation_type=None):
        super(MaecBundleAction,self).__init__(namespace=namespace,idref=idref)
        self.implementation = ActionImplementation()
        self.implementation.id_ = implementation_id
        self.implementation.code=[]
        if implementation_code is not None:
            for code in implementation_code:
                self.implementation.code.append(code)
        self.implementation.api_call = implementation_api_call
        self.implementation.type_ = implementation_type

    def add_action_implementation_api_call(self,api_call):
        self.implementation.type_ = 'api call'
        self.implementation.api_call =api_call

    def create_action_implementation_api_call(self,function_name=None,normalized_function_name=None,address=None,return_value=None,parameters=None,):
        api_call = APICall()
        api_call.function_name = function_name
        api_call.normalized_function_name = normalized_function_name
        api_call.address = address
        api_call.return_value = return_value
        if parameters is not None:
            api_call.parameters = ParameterList()
            for parameter in parameters:
                api_call.parameters.append(parameter)
        return api_call

    def create_action_implementation_api_call_parameter(self,ordinal_position=None,name=None,value=None):
        parameter =  Parameter()
        parameter.ordinal_position = ordinal_position
        parameter.name = name
        parameter.value = value
        return parameter

    def add_action_implementation_code(self,code):
        self.implementation.type_ = 'code'
        self.implementation.code.append(code)

    def create_action_implementation_code(self,type=None,description=None,purpose=None,code_language=None,targeted_platforms=None,processor_family=None,discovery_method=None,
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

    def create_action_implementation_code_targeted_platform(self,description=None,identifiers=None):
        platform = PlatformSpecification()
        if description is not None:
            platform.description= StructuredText(value=description)
        if not identifiers is None:
            for identifier in identifiers:
                platform.identifiers.append(identifier)
        return platform

    def create_action_implementation_code_targeted_platform_identifier(self,system=None,system_ref =None):
        identifier = PlatformIdentifier()
        identifier.system =system
        identifier.system_ref =system_ref
        return identifier


    def create_action_implementation_code_digital_signature(self,signature_verified=None,signature_exists=None,certificate_subject=None,certificate_issuer=None,
                                                          signature_description=None):
        signature = DigitalSignature()
        signature.signature_verified = signature_verified
        signature.signature_exists = signature_exists
        signature.certificate_subject = certificate_subject
        signature.certificate_issuer = certificate_issuer
        signature.signature_description = signature_description
        return signature

    def create_action_implementation_code_extracted_feautures(self,functions=None,imports=None,codesnippets=None,extractedstrings=None):
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


if __name__=='__main__':
    #Testing example
    from mixbox.namespaces import Namespace
    ac = MaecBundleAction(namespace=Namespace('testnamespace','totest','testschemalocation'))
    ac.add_action_name(name='Create Hidden File')
    ####################################################################################################################
    #Add action implementation code or
    from maec_ioc_processor.cybox_discovery_method import CyboxDiscoveryMethod
    dm = CyboxDiscoveryMethod()
    dm.add_discovery_method_name(name='Test behavior discovey method name')
    extrfeat1 = ac.create_action_implementation_code_extracted_feautures(functions=['extr feaut fun 1'],imports=['extr feat imp 1'],codesnippets=['code1 snip'],extractedstrings=['extstring 1'])
    digsign1 = ac.create_action_implementation_code_digital_signature(signature_description='Test signature description 1',signature_exists=True,signature_verified=True,certificate_subject='Test certificate subject 1')
    digsign2 = ac.create_action_implementation_code_digital_signature(signature_description='Test signature description 2',signature_exists=True,signature_verified=True,certificate_subject='Test certificate subject 2')
    ident3 = ac.create_action_implementation_code_targeted_platform_identifier(system='win',system_ref='Test system ref 3')
    platform3 = ac.create_action_implementation_code_targeted_platform(description='Platform 3',identifiers=[ident3])
    dm1 = CyboxDiscoveryMethod()
    dm1.add_discovery_method_name(name = 'Code discovey method')
    code = ac.create_action_implementation_code(type='Test type code',description='Test description',purpose='Test code purpose',code_language='Test code language',
                                              targeted_platforms=[platform3],processor_family=['amd','i386'],discovery_method=dm1,start_address=hex(12355),code_segment='Test code segment',
                                              code_segment_xor='Test xor segment',xor_pattern=hex(11111),digital_signatures=[digsign1,digsign2],extracted_features=extrfeat1)
    #ac.add_action_implementation_code(code)
    ####################################################################################################################
    #Add action implementation api call
    par1 = ac.create_action_implementation_api_call_parameter(ordinal_position=1,name='Par1',value='Val1')
    par2 = ac.create_action_implementation_api_call_parameter(ordinal_position=2,name='Par2',value='Val2')
    api = ac.create_action_implementation_api_call(function_name='API call func name',normalized_function_name='Norm func name',address=hex(11111),return_value=1,parameters=[par1,par2])
    ac.add_action_implementation_api_call(api)
    #Printing results
    print(ac.to_xml())

'''
Created on Oct 29, 2016

@author: davidlepage
'''
import unittest
from .constants import url, api_key, verify
from smc import session
from smc.elements.network import Host
from smc.routing.ospf import OSPFKeyChain, OSPFInterfaceSetting, OSPFArea,\
    OSPFDomainSetting, OSPFProfile
from smc.elements.collection import describe_ospfv2_key_chain,\
    describe_ospfv2_interface_settings, describe_ospfv2_area,\
    describe_ospfv2_profile, describe_ospfv2_domain_settings
from smc.core.engines import Layer3Firewall
from smc.core.engine import Engine
from smc.api.common import SMCRequest

class Test(unittest.TestCase):
    
    def setUp(self):
        session.login(url=url, api_key=api_key, verify=verify)
            
    def tearDown(self):
        try:
            session.logout()
        except SystemExit:
            pass
    
    def test_ospf_key_chain(self):
        key_chain = OSPFKeyChain.create(name='smcpython-keychain', 
                                    key_chain_entry=[{'key': 'fookey',
                                                      'key_id': 10,
                                                      'send_key': True}])
        self.assertEqual(201, key_chain.code)
        
        o = OSPFKeyChain('smcpython-keychain')
        self.assertRegexpMatches(o.href, r'^http')
        
        d = describe_ospfv2_key_chain(name=['smcpython-keychain'])
        result = d[0].delete()
        self.assertEqual(204, result.code)
    
    def test_ospf_key_chain_and_ospf_interface_setting(self):
        key_chain = OSPFKeyChain.create(name='smcpython-keychain', 
                                        key_chain_entry=[{'key': 'fookey',
                                                          'key_id': 10,
                                                          'send_key': True}])
        self.assertEqual(201, key_chain.code)
        ospf_interface = OSPFInterfaceSetting.create(name='smcpython-ospf', 
                                                  authentication_type='message_digest', 
                                                  key_chain_ref=key_chain.href)
        self.assertEqual(201, ospf_interface.code)
        o = OSPFInterfaceSetting('smcpython-ospf')
        self.assertRegexpMatches(o.href, r'^http')
    
        #Delete interface setting first
        e = describe_ospfv2_interface_settings(name=['smcpython-ospf'])
        result = e[0].delete()
        self.assertEqual(204, result.code)
        d = describe_ospfv2_key_chain(name=['smcpython-keychain'])
        result = d[0].delete()
        self.assertEqual(204, result.code)
    
    def test_ospf_area(self):
        
        for profile in describe_ospfv2_interface_settings():
            if profile.name.startswith('Default OSPF'): #Use the system default
                interface_profile = profile.href
    
        area = OSPFArea.create(name='area-smcpython', 
                               interface_settings_ref=interface_profile, 
                               area_id=0)
        self.assertEqual(201, area.code)
        d = describe_ospfv2_area(name=['area-smcpython'])
        result = d[0].delete()
        self.assertEqual(204, result.code)
        
    def test_ospf_domain_and_ospf_profile(self):
    
        domain = OSPFDomainSetting.create(name='smcpython-domain', 
                                          abr_type='cisco')
        self.assertEqual(201, domain.code)
        
        ospf_domain = OSPFDomainSetting('smcpython-domain') #obtain resource

        ospf_profile = OSPFProfile.create(name='smcpython-profile', 
                                          domain_settings_ref=ospf_domain.href)
        self.assertEqual(201, ospf_profile.code)
        o = OSPFProfile('smcpython-profile')
        self.assertRegexpMatches(o.href, r'^http')
        
        #Delete profile first
        d = describe_ospfv2_profile(name=['smcpython-profile'])
        result = d[0].delete()
        self.assertEqual(204, result.code)
        
        e = describe_ospfv2_domain_settings(name=['smcpython-domain'])
        result = e[0].delete()
        self.assertEqual(204, result.code)
        
    def test_create_layer3_firewall_and_add_ospf(self):
        
        for profile in describe_ospfv2_interface_settings():
            if profile.name.startswith('Default OSPF'):
                interface_profile = profile.href

        area = OSPFArea.create(name='smcpython-area', 
                               interface_settings_ref=interface_profile, 
                               area_id=0)
        self.assertEqual(201, area.code)
        
        area = OSPFArea('smcpython-area')

        engine = Layer3Firewall.create(name='smcpython-ospf', 
                                       mgmt_ip='172.18.1.30', 
                                       mgmt_network='172.18.1.0/24', 
                                       domain_server_address=['8.8.8.8'], 
                                       enable_ospf=True)

        self.assertIsInstance(engine, Engine)
        #Get routing resources
        for interface in engine.routing.all(): 
            if interface.name == 'Interface 0':
                result = interface.add_ospf_area(area) #Apply OSPF 'area0' to interface 0
                self.assertEqual(200, result.code)
        
        e = SMCRequest(href=engine.href).delete()
        self.assertEqual(204, e.code)
        
        d = SMCRequest(area.href).delete()
        self.assertEqual(204, d.code)
    
    def test_ospf_unicast(self):
        
        for profile in describe_ospfv2_interface_settings():
            if profile.name.startswith('Default OSPF'):
                interface_profile = profile.href

        area = OSPFArea.create(name='smcpython-area', 
                               interface_settings_ref=interface_profile, 
                               area_id=0)
        self.assertEqual(201, area.code)
        
        area = OSPFArea('smcpython-area')

        engine = Layer3Firewall.create(name='smcpython-ospf', 
                                       mgmt_ip='172.18.1.30', 
                                       mgmt_network='172.18.1.0/24', 
                                       domain_server_address=['8.8.8.8'], 
                                       enable_ospf=True)

        self.assertIsInstance(engine, Engine)
        host = Host.create(name='smcpython-ospf-user', address='23.23.23.23')
        
        #Get routing resources
        for interface in engine.routing.all(): 
            if interface.name == 'Interface 0':
                result = interface.add_ospf_area(area, communication_mode='unicast',
                                                 unicast_ref=host.href)
                self.assertEqual(200, result.code, result)
        
        e = SMCRequest(href=engine.href).delete()
        self.assertEqual(204, e.code)
        
        d = SMCRequest(area.href).delete()
        self.assertEqual(204, d.code)
        
        f = SMCRequest(href=host.href).delete()
        self.assertEqual(204, f.code)
    
            
if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
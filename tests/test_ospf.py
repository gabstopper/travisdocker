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
        self.assertTrue(key_chain.startswith('http'))
        
        o = OSPFKeyChain('smcpython-keychain')
        self.assertRegexpMatches(o.href, r'^http')
        
        # Find and delete through collections
        key_chain = describe_ospfv2_key_chain(name=['smcpython-keychain'])
        key_chain[0].delete()
        
    def test_ospf_key_chain_and_ospf_interface_setting(self):
        key_chain = OSPFKeyChain.create(name='smcpython-keychain', 
                                        key_chain_entry=[{'key': 'fookey',
                                                          'key_id': 10,
                                                          'send_key': True}])
        self.assertTrue(key_chain.startswith('http'))
        ospf_interface = OSPFInterfaceSetting.create(name='smcpython-ospf', 
                                                  authentication_type='message_digest', 
                                                  key_chain_ref=key_chain)
        self.assertTrue(ospf_interface.startswith('http'))
        o = OSPFInterfaceSetting('smcpython-ospf')
        self.assertTrue(o.href.startswith('http'))
        
        #Delete interface setting first
        ospf_intf = describe_ospfv2_interface_settings(name=['smcpython-ospf'])
        ospf_intf[0].delete()
        
        key_chain = describe_ospfv2_key_chain(name=['smcpython-keychain'])
        key_chain[0].delete()
        
    def test_ospf_area(self):
        
        for profile in describe_ospfv2_interface_settings():
            if profile.name.startswith('Default OSPF'): #Use the system default
                interface_profile = profile.href
    
        area = OSPFArea.create(name='area-smcpython', 
                               interface_settings_ref=interface_profile, 
                               area_id=0)
        self.assertTrue(area.startswith('http'))
        
        ospf_area = describe_ospfv2_area(name=['area-smcpython'])
        ospf_area[0].delete()
        
    def test_ospf_domain_and_ospf_profile(self):
    
        domain = OSPFDomainSetting.create(name='smcpython-domain', 
                                          abr_type='cisco')
        self.assertTrue(domain.startswith('http'))
        
        ospf_domain = OSPFDomainSetting('smcpython-domain') #obtain resource

        ospf_profile = OSPFProfile.create(name='smcpython-profile', 
                                          domain_settings_ref=ospf_domain.href)
        self.assertTrue(ospf_profile.startswith('http'))
        
        o = OSPFProfile('smcpython-profile')
        self.assertTrue(o.href.startswith('http'))
        
        #Delete profile first
        ospf_profile = describe_ospfv2_profile(name=['smcpython-profile'])
        ospf_profile[0].delete()
        
        ospf_domain = describe_ospfv2_domain_settings(name=['smcpython-domain'])
        ospf_domain[0].delete()
        
    def test_create_layer3_firewall_and_add_ospf(self):
        
        for profile in describe_ospfv2_interface_settings():
            if profile.name.startswith('Default OSPF'):
                interface_profile = profile.href

        area = OSPFArea.create(name='smcpython-area', 
                               interface_settings_ref=interface_profile, 
                               area_id=0)
        self.assertTrue(area.startswith('http'))
        
        area = OSPFArea('smcpython-area')

        engine = Layer3Firewall.create(name='smcpython-ospf', 
                                       mgmt_ip='172.18.1.30', 
                                       mgmt_network='172.18.1.0/24', 
                                       domain_server_address=['8.8.8.8'], 
                                       enable_ospf=True)

        self.assertIsInstance(engine, Engine)
        # Add IPv6 to make sure OSPF is skipped for that interface
        engine.physical_interface.add_single_node_interface(interface_id=0,
                                                            address='2001:db8:85a3::8a2e:370:7334',
                                                            network_value='2001:db8:85a3::/64')
        #Get routing resources
        for interface in engine.routing.all(): 
            if interface.name == 'Interface 0':
                interface.add_ospf_area(area) #Apply OSPF 'area0' to interface 0
                for networks in interface.all(): #Traverse networks
                    self.assertIn(networks.name, ['network-172.18.1.0/24', 'network-2001:db8:85a3::/64'])
                    self.assertTrue(networks.level == 'network')
        
        #Add only to specified network
        for interface in engine.routing.all():
            if interface.name == 'Interface 0':
                interface.add_ospf_area(area, network='172.18.1.0/24')
            
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
        self.assertTrue(area.startswith('http'))
        
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
                                                 unicast_ref=host)
                self.assertIsNone(result)
        
        engine.delete()
        area.delete()
        
        f = SMCRequest(href=host).delete()
        self.assertEqual(204, f.code)
    
            
if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
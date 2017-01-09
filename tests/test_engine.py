'''
Created on Nov 12, 2016

@author: davidlepage
'''
import unittest
from .constants import url, api_key, verify
from smc import session
from smc.elements.network import Host
from smc.api.exceptions import LoadEngineFailed, EngineCommandFailed,\
    TaskRunFailed, UnsupportedInterfaceType,\
    CertificateError
from smc.core.engine import Engine
from smc.core.engines import Layer3Firewall, MasterEngine, Layer3VirtualEngine,\
    IPS
from smc.core.resource import Alias
from smc.api.common import SMCRequest
from smc.core.node import Node
from smc.api.exceptions import UnsupportedEngineFeature
from smc.vpn.elements import VPNCertificate
from smc.elements.other import prepare_contact_address

class Test(unittest.TestCase):
    def setUp(self):
        session.login(url=url, api_key=api_key, verify=verify,
                      timeout=30)
        
    def tearDown(self):
        try:
            session.logout()
        except SystemExit:
            pass
    
    def test_not_a_firewall_during_load(self):
        Host.create('sometmphost', '1.1.1.1')
        self.assertRaises(LoadEngineFailed, lambda: Engine('sometmphost').load())
        host = Host('sometmphost')
        self.assertEqual(204, host.delete().code)
    
    def test_load_nonexistant_engine(self):
        self.assertRaises(LoadEngineFailed, lambda: Engine('fooooobar').load())
        
    def test_access_before_loading(self):
        if session.api_version <= 6.0:
            engine = Engine('foo')
            self.assertRaises(AttributeError, lambda: engine.nodes)
        else:
            engine = Engine('foo')
            self.assertRaises(LoadEngineFailed, lambda: engine.nodes)
                    
    def test_layer3_engine_methods(self):
        # Test each of the top level engine methods
        engine = Layer3Firewall.create(name='smcpython-fw', 
                                       mgmt_ip='1.1.1.1', 
                                       mgmt_network='1.1.1.0/24')
        self.assertIsInstance(engine, Engine)
        
        if session.api_version >= 6.1:
            test = Engine('smcpython-fw')
            self.assertTrue(test.type == 'single_fw')
            self.assertTrue(test.href.startswith('http'))
            self.assertTrue(test.version is None)
            self.assertTrue(isinstance(test.nodes, list))
        
        # Modify an attribute, i.e. antivirus:
        self.assertIn(engine.modify_attribute(antivirus= 
                                      {'antivirus_enabled': False,
                                       'antivirus_update': 'daily',
                                       'antivirus_update_day': 'mo',
                                       'antivirus_update_time': 21600000,
                                       'virus_log_level': 'none',
                                       'virus_mirror': 'update.nai.com/Products/CommonUpdater'}).code, [200, 201])
        
        # Add a contact address
        for interface in engine.physical_interface.all():
            if interface.name == 'Interface 0':
                contact_address = prepare_contact_address('3.3.3.3', 'templocation')
                result = interface.add_contact_address(contact_address, engine.etag)
                self.assertIn(result.code, [200, 204])
                for address in interface.contact_addresses().get('contact_addresses'):
                    self.assertEqual('3.3.3.3', address.get('address'))
        
        # Test Fail load using wildcard
        Host.create('testengine', '1.1.1.1')
        Host.create('testengine2', '2.2.2.2')
        self.assertRaises(LoadEngineFailed, lambda: Engine('testengine*').load())
        self.assertIn(Host('testengine').delete().code, [200, 204])
        self.assertIn(Host('testengine2').delete().code, [200, 204])
        
                
        #Test reload
        engine = engine.load()
        self.assertIsInstance(engine, Engine)
        
        # Engine type
        self.assertEqual(engine.type, 'single_fw')
        # Get the node type
        self.assertEqual(engine.nodes[0].type, 'firewall_node')
        
        # Iterate nodes
        for node in engine.nodes:
            self.assertIsInstance(node, Node)
            
        # Get permissions, only for SMC API >- 6.1
        if session.api_version >= 6.1:
            self.assertIsInstance(engine.permissions(), dict)
        else:
            self.assertRaises(UnsupportedEngineFeature, lambda: engine.permissions())
        
        # Get aliases
        aliases = engine.alias_resolving()
        for alias in aliases:
            self.assertIsInstance(alias, Alias)
            
        # Blacklist, will fail as engine is not live or connected to SMC
        self.assertRaises(EngineCommandFailed, lambda: engine.blacklist('1.1.1.1/32', '0.0.0.0/0'))
        
        # Blacklist flush, same as above
        self.assertRaises(EngineCommandFailed, lambda: engine.blacklist_flush())
    
        # Add route, valid
        result = engine.add_route('1.1.1.254', '192.168.1.0/24')
        self.assertIsNone(result.msg)
        
        # Add route, invalid, msg attribute set
        result = engine.add_route('2.2.2.2', '10.10.10.0/22')
        self.assertIsNotNone(result.msg)
        
        # Get routes, will catch SMCConnectionException because the engine doesnt
        # exist and will be unresponsive. It should catch and return empty list
        routes = engine.routing_monitoring
        self.assertTrue(len(routes) == 0)
        
        # Get antispoofing info
        spoofing = engine.antispoofing()
        self.assertIsInstance(spoofing.get('antispoofing_node'), list)
        
        self.assertTrue(engine.internal_gateway.name.startswith('smcpython-fw'))
        
        # Get internal gateway
        for gw in engine.internal_gateway.internal_endpoint.all():
            self.assertEqual(gw.name, '1.1.1.1') #matches interface IP
        
        # Get vpn sites
        for sites in engine.internal_gateway.vpn_site.all():
            self.assertRegexpMatches(sites.name, r'^Automatic Site for smcpython-fw')
        
        # Gen certificate for internal gateway, fail because engine can't gen cert
        v = VPNCertificate('myorg', 'foo.org')
        self.assertRaises(CertificateError, lambda: engine.internal_gateway.generate_certificate(v))
        
        # Gateway certificate request, not implemented as of 0.3.7
        self.assertTrue(len(engine.internal_gateway.gateway_certificate()) == 0)
        
        # Gateway certificate, not implemented as of 0.3.7
        self.assertTrue(len(engine.internal_gateway.gateway_certificate_request()) == 0)
        
        # Get a virtual resource on non supported device type
        self.assertRaises(UnsupportedEngineFeature, lambda: engine.virtual_resource)
    
        # Get interfaces
        for intf in engine.interface.all():
            self.assertEqual(intf.name, 'Interface 0')
        
        # Get virtual physical interface, not supported on layer 3 engine
        self.assertRaises(UnsupportedInterfaceType, lambda: engine.virtual_physical_interface)
        
        # Get modem interfaces
        self.assertTrue(len(engine.modem_interface()) == 0)
        
        # Get adsl interfaces
        self.assertTrue(len(engine.adsl_interface()) == 0)
        
        # Get wireless interface
        self.assertTrue(len(engine.wireless_interface()) == 0)
        
        # Get switch interface
        self.assertTrue(len(engine.switch_physical_interface()) == 0)
        
        # Get tunnel interfaces
        result = engine.tunnel_interface.add_single_node_interface(tunnel_id=1000, 
                                                                   address='2.2.2.2', 
                                                                   network_value='2.2.2.0/24')
        self.assertEqual(201, result.code)
        
        # Query tunnel interfaces
        for intf in engine.tunnel_interface.all():
            self.assertEqual(intf.name, 'Tunnel Interface 1000')
                
        # Refresh policy, fails as engine not ready
        self.assertRaises(TaskRunFailed, lambda: engine.refresh())
        
        # Upload, policy doesn't exist
        self.assertRaises(TaskRunFailed, lambda: engine.upload(policy='foo'))
        
        # Generate snapshot #TODO: Bug
        # print engine.generate_snapshot()
        # 
        
        #See snapshots. Policy hasnt been pushed yet so they wont exist
        self.assertTrue(len(engine.snapshots()) == 0)

        # Delete
        d = SMCRequest(engine.href).delete()
        self.assertEqual(204, d.code)
        
    def test_virtual_engine_with_unsupported_methods(self):

        master = MasterEngine.create(name='smcpython-me', 
                                     master_type='firewall', 
                                     mgmt_ip='1.1.1.1', 
                                     mgmt_netmask='1.1.1.0/24')
        self.assertIsInstance(master, Engine)
        
        result = master.virtual_resource.create(name='ve-1', vfw_id=1)
        self.assertEqual(201, result.code)
        
        layer3ve = Layer3VirtualEngine.create(name='myve', 
                                              master_engine='smcpython-me', 
                                              virtual_resource='ve-1', 
                                              interfaces=[{'address': '2.2.2.2',
                                                           'network_value': '2.2.2.0/24',
                                                           'interface_id': 0}])
        self.assertIsInstance(layer3ve, Engine)
        for intf in layer3ve.virtual_physical_interface.all():
            self.assertTrue(intf.name == 'Interface 0')
        
        # Verify virtual resource name and vfw id for master engine
        for x in master.virtual_resource.all():
            self.assertTrue(x.name == 've-1')
            self.assertTrue(x.vfw_id==1)
          
        self.assertRaises(UnsupportedInterfaceType, lambda: layer3ve.physical_interface)

        # Delete VE first
        d = SMCRequest(href=layer3ve.href).delete()
        self.assertEqual(204, d.code)
        e = SMCRequest(href=master.href).delete()
        self.assertEqual(204, e.code)
        
    def test_unsupported_internal_gw(self):
        # IPS does not support internal gateways, just verify it fails
        engine = IPS.create(name='smcpython-ips', 
                            mgmt_ip='1.1.1.1', 
                            mgmt_network='1.1.1.0/24')
        self.assertIsInstance(engine, Engine)
        
        # Internal gateways for VPN are not supported on L2 or IPS
        self.assertRaises(UnsupportedEngineFeature, lambda: engine.internal_gateway)
        
        # Tunnel interfaces are only supported on layer 3
        self.assertRaises(UnsupportedInterfaceType, lambda: engine.tunnel_interface)
        
        d = SMCRequest(href=engine.href).delete()
        self.assertEqual(204, d.code)
    
    def test_rename_engine(self):
        # Test renaming the engine
        engine = Layer3Firewall.create(name='smc-python', 
                                       mgmt_ip='1.1.1.1', 
                                       mgmt_network='1.1.1.0/24')
        self.assertIsInstance(engine, Engine)
        
        engine.rename('smc-python2')
        
        self.assertEqual(engine.name, 'smc-python2')
        for node in engine.nodes:
            self.assertTrue(node.name.startswith('smc-python2'))
        
        self.assertTrue(engine.internal_gateway.name.startswith('smc-python2'))
        
        d = SMCRequest(href=engine.href).delete()
        self.assertEqual(204, d.code)

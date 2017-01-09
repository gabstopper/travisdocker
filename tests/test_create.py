'''
Created on Jun 25, 2016

@author: davidlepage
'''
import unittest
from .constants import url, api_key, verify
from smc import session
from smc.elements.helpers import zone_helper, logical_intf_helper,\
    location_helper
from smc.core.engines import Layer2Firewall, Layer3Firewall, IPS, FirewallCluster,\
    MasterEngine, Engine, Layer3VirtualEngine, MasterEngineCluster
from smc.api.exceptions import LoadEngineFailed, CreateEngineFailed
from smc.api.common import SMCRequest
from smc.elements.network import Host
from smc.elements.other import prepare_contact_address
from smc.core.interfaces import PhysicalInterface, Interface

class Test(unittest.TestCase):
    tmp = {}
    def setUp(self):
        session.login(url=url, api_key=api_key, verify=verify,
                      timeout=40)
        
    def tearDown(self):
        try:
            session.logout()
        except SystemExit:
            pass
  
    #@unittest.skip("tmp")    
    def testSingleFW(self):
        
        loc = location_helper('anapilocation')
        #First test the raw creation
        engine = Layer3Firewall.create(name='myfw', 
                                       mgmt_ip='1.1.1.1', 
                                       mgmt_network='1.1.1.0/24',
                                       enable_antivirus=True,
                                       enable_gti=True,
                                       default_nat=True,
                                       location_ref=loc,
                                       domain_server_address=['8.8.8.8'])
        self.assertIsInstance(engine, Engine)
        r = engine.physical_interface.add_single_node_interface(1, '2.2.2.2', '2.2.2.0/24',
                                                                zone_ref=zone_helper('Internal'))
        self.assertTrue(r.href.startswith('http'))
        r = engine.physical_interface.add_vlan_to_single_node_interface(2, '3.3.3.3', '3.3.3.0/24', 
                                                   vlan_id=3, zone_ref=zone_helper('Internal'))
        self.assertTrue(r.href.startswith('http'))
        for interface in engine.interface.all():
            data = interface.describe()
            if interface.name == 'Interface 1':
                self.assertTrue(data.get('zone_ref').startswith('http'))
                for typeof, values in data.get('interfaces')[0].items():
                    self.assertEqual(typeof, 'single_node_interface')
                    self.assertEqual(values.get('address'), '2.2.2.2')
                    self.assertEqual(values.get('network_value'), '2.2.2.0/24')
            elif interface.name == 'Interface 2':
                vlanInterfaces = data.get('vlanInterfaces')[0]
                self.assertEqual(vlanInterfaces.get('interface_id'), '2.3')
                self.assertTrue(vlanInterfaces.get('zone_ref').startswith('http'))
                for typeof, values in vlanInterfaces.get('interfaces')[0].items():
                    self.assertEqual(typeof, 'single_node_interface')
                    self.assertEqual(values.get('address'), '3.3.3.3')
                    self.assertEqual(values.get('network_value'), '3.3.3.0/24')
                    self.assertEqual(values.get('nicid'), '2.3')

        self.assertEqual(engine.delete().code, 204)
    
    #@unittest.skip("tmp")  
    def test_singlefw_fail_create(self):
        # Catch the create fail exception
        Host.create('smcpython-fw', '1.1.1.1')
        self.assertRaises(CreateEngineFailed, lambda: Layer3Firewall.create(name='smcpython-fw', 
                                                                            mgmt_ip='1.1.1.1', 
                                                                            mgmt_network='1.1.1.0/24'))
        self.assertEqual(Host('smcpython-fw').delete().code, 204)     
                    
      
    #@unittest.skip("tmp")    
    def testSingleLayer2(self):
        """ Test create of layer 2 through smc.actions.shortcuts """
        
        engine = Layer2Firewall.create('l2', '1.1.1.1', '1.1.1.0/24')
        self.assertIsInstance(engine, Engine)
        r = engine.physical_interface.add_capture_interface(10, logical_interface_ref=logical_intf_helper('Inline'), 
                                                            zone_ref=zone_helper('Internal'))
        self.assertTrue(r.href.startswith('http'))
        
        r = engine.physical_interface.add_inline_interface('11-12', logical_interface_ref=logical_intf_helper('default_eth'))
        self.assertTrue(r.href.startswith('http'))
        
        r= engine.physical_interface.add_vlan_to_inline_interface('5-6', 56, 
                                       logical_interface_ref=logical_intf_helper('default_eth'))
        self.assertTrue(r.href.startswith('http'))
        r= engine.physical_interface.add_vlan_to_inline_interface('5-6', 57, 
                                       logical_interface_ref=logical_intf_helper('default_eth'))
        self.assertTrue(r.href.startswith('http'))
        r = engine.physical_interface.add_vlan_to_inline_interface('5-6', 58, 
                                       logical_interface_ref=logical_intf_helper('default_eth'),
                                       zone_ref_intf1=zone_helper('Internal'),
                                       zone_ref_intf2=zone_helper('DMZ'))
        self.assertTrue(r.href.startswith('http'))
        
        r = engine.physical_interface.add_vlan_to_inline_interface('7-8', vlan_id=100, vlan_id2=101,
                                                                   logical_interface_ref=logical_intf_helper('default_eth'))
        self.assertTrue(r.href.startswith('http'))
        
        SMCRequest(href=engine.href).delete()
    
    #@unittest.skip("tmp")  
    def test_layer2_fail_create(self):
        # Catch the create fail exception
        Host.create('smcpython-fw', '1.1.1.1')
        self.assertRaises(CreateEngineFailed, lambda: Layer2Firewall.create(name='smcpython-fw', 
                                                                            mgmt_ip='1.1.1.1', 
                                                                            mgmt_network='1.1.1.0/24'))
        self.assertEqual(Host('smcpython-fw').delete().code, 204)     
        
    #@unittest.skip("tmp")    
    def testSingleIPS(self):
        """ Test IPS creation through smc.actions.shortcuts """
        
        engine = IPS.create('ips', 
                        '1.1.1.1', 
                        '1.1.1.0/24', 
                        mgmt_interface=4, 
                        domain_server_address=['8.8.8.8'], 
                        zone_ref=zone_helper('Internal'))
        self.assertIsInstance(engine, Engine)
        r = engine.physical_interface.add_capture_interface(10, logical_interface_ref=logical_intf_helper('Inline'), 
                                                        zone_ref=zone_helper('Internal'))
        self.assertTrue(r.href.startswith('http'))
        r = engine.physical_interface.add_inline_interface('11-12', logical_interface_ref=logical_intf_helper('default_eth'))
        self.assertTrue(r.href.startswith('http'))
        
        r= engine.physical_interface.add_vlan_to_inline_interface('5-6', 56, 
                                       logical_interface_ref=logical_intf_helper('default_eth'))
        self.assertTrue(r.href.startswith('http'))
        r= engine.physical_interface.add_vlan_to_inline_interface('5-6', 57, 
                                       logical_interface_ref=logical_intf_helper('default_eth'))
        self.assertTrue(r.href.startswith('http'))
        r = engine.physical_interface.add_vlan_to_inline_interface('5-6', 58, 
                                       logical_interface_ref=logical_intf_helper('default_eth'),
                                       zone_ref_intf1=zone_helper('Internal'),
                                       zone_ref_intf2=zone_helper('DMZ'))
        self.assertTrue(r.href.startswith('http'))
        SMCRequest(href=engine.href).delete()
    
    #@unittest.skip("tmp")  
    def test_ips_fail_create(self):
        Host.create('smcpython-fw', '1.1.1.1')
        self.assertRaises(CreateEngineFailed, lambda: IPS.create(name='smcpython-fw', 
                                                                 mgmt_ip='1.1.1.1', 
                                                                 mgmt_network='1.1.1.0/24'))
        self.assertEqual(Host('smcpython-fw').delete().code, 204)  
        
    #@unittest.skip("tmp")
    def testNotFoundNode(self):
        #not found node in SMC
        self.assertRaises(LoadEngineFailed, lambda: Engine('ergergserger').load())
    
    #@unittest.skip("tmp")    
    def testFirewallCluster(self):
                
        engine = FirewallCluster.create(name='mycluster', 
                                    cluster_virtual='1.1.1.1', 
                                    cluster_mask='1.1.1.0/24',
                                    cluster_nic=0,
                                    macaddress='02:02:02:02:02:02',
                                    nodes=[{'address': '1.1.1.2', 'network_value': '1.1.1.0/24', 'nodeid':1},
                                           {'address': '1.1.1.3', 'network_value': '1.1.1.0/24', 'nodeid':2},
                                           {'address': '1.1.1.4', 'network_value': '1.1.1.0/24', 'nodeid':3}],
                                    domain_server_address=['1.1.1.1'], 
                                    zone_ref=zone_helper('Internal'))
        self.assertIsInstance(engine, Engine)
        r = engine.physical_interface.add_cluster_virtual_interface(
                                            interface_id=1,
                                            cluster_virtual='5.5.5.1', 
                                            cluster_mask='5.5.5.0/24', 
                                            macaddress='02:03:03:03:03:03', 
                                            nodes=[{'address':'5.5.5.2', 'network_value':'5.5.5.0/24', 'nodeid':1},
                                                   {'address':'5.5.5.3', 'network_value':'5.5.5.0/24', 'nodeid':2},
                                                   {'address':'5.5.5.4', 'network_value':'5.5.5.0/24', 'nodeid':3}],
                                            zone_ref=zone_helper('Heartbeat'))
        self.assertTrue(r.href.startswith('http'))
        SMCRequest(href=engine.href).delete()
    
    #@unittest.skip("tmp")  
    def test_firewallcluster_fail_create(self):
        Host.create('smcpython-fw', '1.1.1.1')
        self.assertRaises(CreateEngineFailed, lambda: FirewallCluster.create(name='smcpython-fw', 
                                    cluster_virtual='1.1.1.1', 
                                    cluster_mask='1.1.1.0/24',
                                    cluster_nic=0,
                                    macaddress='02:02:02:02:02:02',
                                    nodes=[{'address': '1.1.1.2', 'network_value': '1.1.1.0/24', 'nodeid':1},
                                           {'address': '1.1.1.3', 'network_value': '1.1.1.0/24', 'nodeid':2},
                                           {'address': '1.1.1.4', 'network_value': '1.1.1.0/24', 'nodeid':3}],
                                    domain_server_address=['1.1.1.1'], 
                                    zone_ref=zone_helper('Internal')))
        self.assertEqual(Host('smcpython-fw').delete().code, 204) 
         
    #@unittest.skip("tmp")   
    def testMasterEngine(self):
        
        engine = MasterEngine.create('api-master',
                                     mgmt_ip='1.1.1.1',
                                     mgmt_netmask='1.1.1.0/24',
                                     master_type='firewall', 
                                     domain_server_address=['8.8.8.8', '7.7.7.7'])
        self.assertIsInstance(engine, Engine)
        r = engine.physical_interface.add(1)
        self.assertTrue(r.href.startswith('http'))
        r = engine.physical_interface.add(2)
        self.assertTrue(r.href.startswith('http'))
        r = engine.physical_interface.add(3)
        self.assertTrue(r.href.startswith('http'))
        
        SMCRequest(href=engine.href).delete()
    
    def test_master_engine_fail_create(self):
        Host.create('smcpython-fw', '1.1.1.1')
        self.assertRaises(CreateEngineFailed, lambda: MasterEngine.create('smcpython-fw',
                                                             mgmt_ip='1.1.1.1',
                                                             mgmt_netmask='1.1.1.0/24',
                                                             master_type='firewall', 
                                                             domain_server_address=['8.8.4.4', '7.7.7.7']))
        self.assertEqual(Host('smcpython-fw').delete().code, 204) 
        
    def test_masterengine_with_virtual(self):
        #Single master engine, no cluster
        engine = MasterEngine.create('api-master',
                                     mgmt_ip='1.1.1.1',
                                     mgmt_netmask='1.1.1.0/24',
                                     master_type='firewall', 
                                     domain_server_address=['8.8.4.4', '7.7.7.7'])
        self.assertIsInstance(engine, Engine)
        
        virtual = engine.virtual_resource.create(name='ve-1', vfw_id=1)
        self.assertEqual(201, virtual.code)
        
        result = engine.physical_interface.add(interface_id=1, virtual_mapping=0,
                                               virtual_resource_name='ve-1')
        self.assertEqual(201, result.code)
        
        # Fail due to missing virtual resource
        self.assertRaises(CreateEngineFailed, lambda: 
                                Layer3VirtualEngine.create(
                                    name='myvirtual', 
                                    master_engine='api-master', 
                                    virtual_resource='foo', 
                                    interfaces=[{'address': '1.1.1.1',
                                                 'network_value': '1.1.1.0/24',
                                                 'interface_id': 0}]))

        # Valid virtual resource
        virtualengine = Layer3VirtualEngine.create(
                                    name='myvirtual', 
                                    master_engine='api-master', 
                                    virtual_resource='ve-1', 
                                    interfaces=[{'address': '1.1.1.1',
                                                 'network_value': '1.1.1.0/24',
                                                 'interface_id': 0}])
        
        # Fail creating virtual resource (name already exists)
        self.assertRaises(CreateEngineFailed, lambda: 
                                Layer3VirtualEngine.create(
                                    name='myvirtual', 
                                    master_engine='api-master', 
                                    virtual_resource='ve-1', 
                                    interfaces=[{'address': '1.1.1.1',
                                                 'network_value': '1.1.1.0/24',
                                                 'interface_id': 0}]))
        
        self.assertIsInstance(virtualengine, Engine)
        a = virtualengine.delete()
        self.assertEqual(204, a.code)
        b = engine.delete()
        self.assertEqual(204, b.code)
              
    #@unittest.skip("tmp")
    def testVirtualLayer3Engine(self):
        
        masterengine = MasterEngine.create('api-master',
                                     mgmt_ip='1.1.1.1',
                                     mgmt_netmask='1.1.1.0/24',
                                     master_type='firewall', 
                                     domain_server_address=['8.8.4.4', '7.7.7.7'])
        
        virtual_resource = masterengine.virtual_resource.create(name='ve-10', vfw_id=1)
        self.assertEqual(201, virtual_resource.code)
        
        result = masterengine.physical_interface.add_vlan_to_node_interface(interface_id=1, 
                                                                      vlan_id=100, 
                                                                      virtual_mapping=0, 
                                                                      virtual_resource_name='ve-10')
        self.assertEquals(201, result.code)
        
        #Master engine must exist and be online or interface will show with red X through it
        engine = Layer3VirtualEngine.create('layer3-ve', 
                                             master_engine='api-master', 
                                             virtual_resource='ve-10',
                                             interfaces=[{'interface_id': 0,
                                                          'address': '1.1.1.1',
                                                          'network_value': '1.1.1.0/24'}])
        self.assertIsInstance(engine, Engine)
        a = SMCRequest(href=engine.href).delete()
        self.assertEqual(204, a.code)
        b = SMCRequest(href=masterengine.href).delete()
        self.assertEqual(204, b.code)
    
    #@unittest.skip("tmp")  
    def test_masterEngine_cluster(self):
        #Test creating MasterEngineCluster
        engine = MasterEngineCluster.create(
                                    name='engine-cluster',
                                    master_type='firewall', 
                                    macaddress='22:22:22:22:22:22', 
                                    nodes=[{'address':'5.5.5.2', 
                                            'network_value':'5.5.5.0/24', 
                                            'nodeid':1},
                                           {'address':'5.5.5.3', 
                                            'network_value':'5.5.5.0/24', 
                                            'nodeid':2}])
        self.assertIsInstance(engine, Engine)
        #Create another interface
        result = engine.physical_interface.add_cluster_interface_on_master_engine(
                                        interface_id=1,
                                        macaddress='22:22:22:22:22:33', 
                                        nodes=[{'address': '6.6.6.2',
                                                'network_value': '6.6.6.0/24',
                                                'nodeid':1},
                                                {'address':'6.6.6.3',
                                                 'network_value':'6.6.6.0/24',
                                                 'nodeid':2}])
        self.assertEqual(201, result.code)
        
        #Simulate failed creation of master engine (preexisting with same name)
        self.assertRaises(CreateEngineFailed, lambda:
                                MasterEngineCluster.create(
                                    name='engine-cluster',
                                    master_type='firewall', 
                                    macaddress='22:22:22:22:22:22', 
                                    nodes=[{'address':'5.5.5.2', 
                                            'network_value':'5.5.5.0/24', 
                                            'nodeid':1},
                                           {'address':'5.5.5.3', 
                                            'network_value':'5.5.5.0/24', 
                                            'nodeid':2}]))

        a = SMCRequest(href=engine.href).delete()
        self.assertEqual(204, a.code)
    
    #@unittest.skip("tmp")      
    def test_full_masterenginecluster_with_virtualengines(self):
        engine = MasterEngineCluster.create(
                                    name='engine-cluster',
                                    master_type='firewall', 
                                    macaddress='22:22:22:22:22:22', 
                                    nodes=[{'address':'5.5.5.2', 
                                            'network_value':'5.5.5.0/24', 
                                            'nodeid':1},
                                           {'address':'5.5.5.3', 
                                            'network_value':'5.5.5.0/24', 
                                            'nodeid':2}])
        self.assertIsInstance(engine, Engine)
        
        result = engine.virtual_resource.create(name='ve-1', vfw_id=1)
        self.assertEqual(201, result.code)
        
        result = engine.physical_interface.add_vlan_to_node_interface(
                                                        interface_id=1,
                                                        vlan_id=100, 
                                                        virtual_mapping=0, 
                                                        virtual_resource_name='ve-1')
        self.assertEqual(201, result.code)
        
        engine = Layer3VirtualEngine.create('layer3-ve', 
                                            master_engine='engine-cluster', 
                                            virtual_resource='ve-1',
                                            interfaces=[{'interface_id': 0,
                                                         'address': '1.1.1.1',
                                                         'network_value': '1.1.1.0/24'}])
        self.assertIsInstance(engine, Engine)
        d = engine.delete()
        self.assertEqual(204, d.code)
        e = Engine('engine-cluster').load().delete()
        self.assertEqual(204, e.code)
       
    def test_tunnel_and_dhcp_interface(self):
        engine = Layer3Firewall.create('myfw', 
                                   '1.1.1.1', 
                                   '1.1.1.0/24')
        self.assertIsInstance(engine, Engine)
        
        result = engine.tunnel_interface.add_single_node_interface(tunnel_id=1000, 
                                                                   address='2.2.2.2', 
                                                                   network_value='2.2.2.0/24')
        self.assertIn(result.code, [201,200])

        for interface in engine.interface.all():
            self.assertIsInstance(interface, Interface)
        
        result = engine.physical_interface.add_dhcp_interface(interface_id=20, 
                                                              dynamic_index=1, 
                                                              zone_ref=zone_helper('Internal'))
        self.assertIn(result.code, [201, 200])    
        self.assertEqual(engine.delete().code, 204)
    
    def test_tunnel_cvi_ndi(self):
        engine = FirewallCluster.create(name='mycluster', 
                                        cluster_virtual='1.1.1.1', 
                                        cluster_mask='1.1.1.0/24',
                                        cluster_nic=0,
                                        macaddress='02:02:02:02:02:02',
                                        nodes=[{'address': '1.1.1.2', 'network_value': '1.1.1.0/24', 'nodeid':1},
                                               {'address': '1.1.1.3', 'network_value': '1.1.1.0/24', 'nodeid':2},
                                               {'address': '1.1.1.4', 'network_value': '1.1.1.0/24', 'nodeid':3}],
                                        domain_server_address=['1.1.1.1'], 
                                        zone_ref=zone_helper('Internal'))
        self.assertIsInstance(engine, Engine)
        # Add just a CVI
        result = engine.tunnel_interface.add_cluster_virtual_interface(tunnel_id=1001, 
                                                                       address='23.23.23.23', 
                                                                       network_value='23.23.23.0/24')
        self.assertIn(result.code, [200, 201])
        # Add CVI and NDI (no mac required for Tunnel Interface)
        result = engine.tunnel_interface.add_cluster_virtual_and_node_interfaces(
                    tunnel_id=1055, 
                    address='77.77.77.77', 
                    network_value='77.77.77.0/24', 
                    nodes=[{'address':'77.77.77.78', 'network_value':'77.77.77.0/24', 'nodeid':1},
                           {'address':'77.77.77.79', 'network_value':'77.77.77.0/24', 'nodeid':2},
                           {'address':'77.77.77.80', 'network_value':'77.77.77.0/24', 'nodeid': 3}])
        
        self.assertIn(result.code, [200,201])
        self.assertEqual(engine.delete().code, 204)
        
    def test_contact_addr_on_physical_and_tunnel(self):
        engine = Layer3Firewall.create('myfw', 
                                       '1.1.1.1', 
                                       '1.1.1.0/24')
        self.assertIsInstance(engine, Engine)
        
        # Add contact address
        for intf in engine.physical_interface.all():
            if intf.name == 'Interface 0':
                contact_address = prepare_contact_address('53.2.4.3', 'Default')
                self.assertIn(intf.add_contact_address(contact_address, engine.etag).code, [200, 201])
        # View contact address
        for intf in engine.physical_interface.all():
            if intf.name == 'Interface 0':
                addr = intf.contact_addresses().get('contact_addresses')
                self.assertTrue(addr[0].get('address') == '53.2.4.3')
                
        self.assertEqual(engine.delete().code, 204)
    
    def test_attribute_error_on_physical_interface(self):
        physical = PhysicalInterface()
        self.assertRaises(AttributeError, lambda: physical.link) 
  
if __name__ == "__main__":
    unittest.main()
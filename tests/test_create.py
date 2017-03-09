'''
Created on Jun 25, 2016

@author: davidlepage
'''
import unittest
from constants import url, api_key, verify
from smc import session
from smc.elements.helpers import zone_helper, logical_intf_helper,\
    location_helper
from smc.core.engines import Layer2Firewall, Layer3Firewall, IPS, FirewallCluster,\
    MasterEngine, Engine, Layer3VirtualEngine, MasterEngineCluster
from smc.api.exceptions import LoadEngineFailed, CreateEngineFailed,\
    EngineCommandFailed, DeleteElementFailed
from smc.elements.network import Host, Alias, Network
from smc.elements.other import ContactAddress
from smc.core.interfaces import PhysicalInterface,\
    PhysicalVlanInterface, TunnelInterface
from smc.core.sub_interfaces import SingleNodeInterface, CaptureInterface,\
    InlineInterface

class Test(unittest.TestCase):
    
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
        engine.physical_interface.add_single_node_interface(1, '2.2.2.2', '2.2.2.0/24',
                                                            zone_ref=zone_helper('Internal'))
        
        engine.physical_interface.add_vlan_to_single_node_interface(2, '3.3.3.3', '3.3.3.0/24', 
                                                                    vlan_id=3, 
                                                                    zone_ref=zone_helper('Internal'))
        # Invalid netmask
        with self.assertRaises(EngineCommandFailed):
            engine.physical_interface.add_single_node_interface(interface_id=10, 
                                                                address='10.10.10.10', 
                                                                network_value='10.10.10.10')
        
        # Add another interface to interface 1
        engine.physical_interface.add_single_node_interface(interface_id=1, 
                                                            address='22.22.22.22', 
                                                            network_value='22.22.22.0/24')
        
        # Add empty interface and verify adding IP address afterwards works
        engine.physical_interface.add(20)
        engine.physical_interface.add_single_node_interface(interface_id=20, 
                                                        address='11.11.11.11', 
                                                        network_value='11.11.11.0/24')
        
        engine.physical_interface.add_single_node_interface(interface_id=21, 
                                                            address='2001:db8:85a3::8a2e:370:7334', 
                                                            network_value='2001:db8:85a3::/64')
          
        for interface in engine.interface.all():
            if interface.name == 'Interface 1':
                self.assertTrue(interface.zone_ref.startswith('http'))
                for sub_intf in interface.sub_interfaces():
                    self.assertIsInstance(sub_intf, SingleNodeInterface)
                    self.assertIn(sub_intf.address, ['2.2.2.2', '22.22.22.22'])
                    self.assertIn(sub_intf.network_value, ['2.2.2.0/24', '22.22.22.0/24'])
            
            elif interface.name == 'Interface 2':
                info = (list(zip(interface.address, interface.network_value, interface.nicid)))
                address, network, nicid = info[0]
                self.assertEqual(address, '3.3.3.3')
                self.assertEqual(network, '3.3.3.0/24')
                self.assertEqual(nicid, '2.3')
            
            elif interface.name == 'Interface 20':
                for sub_intf in interface.sub_interfaces():
                    self.assertIsInstance(sub_intf, SingleNodeInterface)
                    self.assertEqual(sub_intf.address, '11.11.11.11')
                    self.assertEqual(sub_intf.network_value, '11.11.11.0/24')
            
            elif interface.name == 'Interface 21':
                for sub_intf in interface.sub_interfaces():
                    self.assertIsInstance(sub_intf, SingleNodeInterface)
                    self.assertEqual(sub_intf.address, '2001:db8:85a3::8a2e:370:7334')
                    self.assertEqual(sub_intf.network_value, '2001:db8:85a3::/64')
                    
        # Test getting interfaces
        # Doesn't exist
        self.assertRaises(EngineCommandFailed, lambda: engine.physical_interface.get(10))
        # Existing
        intf = engine.physical_interface.get(0)
        # Add zone
        zone = zone_helper('Zoner')
        intf.zone_ref = zone
        self.assertIsNone(intf.save())
        self.assertEqual(intf.zone_ref, zone)
        
        # Force refresh of cache after save. This will trigger the
        # HTTP 304 meaning the server side changed before cache was refreshed
        zone = zone_helper("ForceRefresh")
        intf.zone_ref = zone
        self.assertIsNone(intf.save())
        
        # Double check delete interface
        engine.physical_interface.add_single_node_interface(interface_id=10, 
                                                            address='10.10.10.10', 
                                                            network_value='10.10.10.0/24')
        intf = engine.physical_interface.get(10)
        self.assertIsInstance(repr(intf), str) #SubElement __repr__ through UnicodeMixin
        self.assertIsInstance(intf, PhysicalInterface)
        self.assertTrue(intf.has_interfaces)
        self.assertIsNone(intf.delete())
        
        # Add a physical interface with a single VLAN, no IP Address
        engine.physical_interface.add_vlan_to_node_interface(interface_id=20, 
                                                             vlan_id=20)
        # Verify that a PhysicalVlanInterface type is returned
        for x in engine.interface.all():
            if x.name == 'Interface 20':
                self.assertIsInstance(x.sub_interfaces()[0], PhysicalVlanInterface)
        
        # Now add the IP Address to the VLAN interface
        r = engine.physical_interface.add_ipaddress_to_vlan_interface(20, address='21.21.21.21', 
                                                                      network_value='21.21.21.0/24',
                                                                      vlan_id=20)
        self.assertIsNone(r)
        
        # The interface does not exist!
        with self.assertRaises(EngineCommandFailed):
            engine.physical_interface.add_ipaddress_to_vlan_interface(25, address='21.21.21.21', 
                                                                      network_value='21.21.21.0/24',
                                                                      vlan_id=20)
        
        # Add Tunnel interfaces
        engine.tunnel_interface.add_single_node_interface(tunnel_id=1000, 
                                                          address='100.100.100.100', 
                                                          network_value='100.100.100.0/24')
        # Add another IP to this Tunnel
        engine.tunnel_interface.add_single_node_interface(tunnel_id=1000, 
                                                          address='110.110.110.110', 
                                                          network_value='110.110.110.0/24')
        
        
        # Get aliases
        aliases = engine.alias_resolving()
        for alias in aliases:
            self.assertIsInstance(alias, Alias)
            self.assertIsNotNone(alias.name)
            self.assertTrue(alias.href.startswith('http'))
            self.assertIsInstance(alias.resolved_value, list)
           
        #Resolve the IP address alias for this engine
        alias = Alias('$$ Interface ID 0.ip')
        self.assertIn('1.1.1.1', alias.resolve('myfw'))
        
        #Antispoofing
        Network.create(name='network-10.1.2.0/24', ipv4_network='10.1.2.0/24')
        spoofing = engine.antispoofing
        self.assertIsInstance(spoofing, Antispoofing)
        for entry in engine.antispoofing.all(): 
            if entry.name == 'Interface 0':
                self.assertEqual(entry.level, 'interface')
                self.assertEqual(entry.validity, 'enable')
                entry.add(Network('network-10.1.2.0/24'))
        
        #Look for our network
        for entry in engine.antispoofing.all():
            if entry.name == 'Interface 0':
                for network in entry.all():
                    if network.name == 'network-10.1.2.0/24':
                        self.assertEqual(network.ip, '10.1.2.0/24')
        
        # Test renaming NGFW               
        engine.rename('smc-python')
        
        self.assertEqual(engine.name, 'smc-python')
        for node in engine.nodes:
            self.assertTrue(node.name.startswith('smc-python'))
        self.assertTrue(engine.internal_gateway.name.startswith('smc-python'))
        
        # Gen certificate for internal gateway, fail because engine can't gen cert when uninitialized
        v = VPNCertificate('myorg', 'foo.org')
        self.assertRaises(CertificateError, lambda: engine.internal_gateway.generate_certificate(v))
        
        #Modify an attribute on engine using lower level modify_attribute
        #Requires key value. Replaces full nested dict in this case.
        response = engine.modify_attribute(scan_detection={'scan_detection_icmp_events': 250,
                                                           'scan_detection_icmp_timewindow': 1,
                                                           'scan_detection_tcp_events': 220,
                                                           'scan_detection_tcp_timewindow': 1,
                                                           'scan_detection_type': 'default off',
                                                           'scan_detection_udp_events': 220,
                                                           'scan_detection_udp_timewindow': 1})
        self.assertIsNone(response)
        result = engine.attr_by_name('scan_detection')
        self.assertEqual(result.get('scan_detection_icmp_events'), 250)
        
        for _ in engine.export(filename='export.zip', wait_for_finish=True):
            pass
        
        engine.delete()
        Network('network-10.1.2.0/24').delete()
        # Adding an IP to an existing interface requires this to occur through an engine
        # reference as we first need to successfully retrieve the interface
        physical = PhysicalInterface()
        with self.assertRaises(EngineCommandFailed):
            physical.add_ipaddress_to_vlan_interface(interface_id=15, 
                                                     address='15.15.15.15', 
                                                     network_value='15.15.15.0/24',
                                                     vlan_id=15)
    
    def test_singlefw_fail_create(self):
        # Catch the create fail exception
        Host.create('smcpython-fw', '1.1.1.1')
        with self.assertRaises(CreateEngineFailed):
            Layer3Firewall.create(name='smcpython-fw', 
                                  mgmt_ip='1.1.1.1',
                                  mgmt_network='1.1.1.0/24')
      
        Host('smcpython-fw').delete()    
                    
      
    #@unittest.skip("tmp")    
    def testSingleLayer2(self):
        """ Test create of layer 2 through smc.actions.shortcuts """
        
        engine = Layer2Firewall.create('l2', '1.1.1.1', '1.1.1.0/24')
        self.assertIsInstance(engine, Engine)
        engine.physical_interface.add_capture_interface(10, 
                                            logical_interface_ref=logical_intf_helper('Inline'), 
                                            zone_ref=zone_helper('Internal'))
        
        engine.physical_interface.add_inline_interface(interface_id='11-12', 
                                            logical_interface_ref=logical_intf_helper('default_eth'))
        
        engine.physical_interface.add_vlan_to_inline_interface('5-6', 56, 
                                            logical_interface_ref=logical_intf_helper('default_eth'))
        
        engine.physical_interface.add_vlan_to_inline_interface('5-6', 57, 
                                            logical_interface_ref=logical_intf_helper('default_eth'))
        
        engine.physical_interface.add_vlan_to_inline_interface('5-6', 58, 
                                            logical_interface_ref=logical_intf_helper('default_eth'),
                                            zone_ref_intf1=zone_helper('Internal'),
                                            zone_ref_intf2=zone_helper('DMZ'))
        
        engine.physical_interface.add_vlan_to_inline_interface('7-8', vlan_id=100, vlan_id2=101,
                                            logical_interface_ref=logical_intf_helper('default_eth'))
        
        # Add a layer 3 node interface with VLAN, no address
        engine.physical_interface.add_vlan_to_node_interface(interface_id=21, vlan_id=21)
        
        # Add the IP address to this VLAN
        engine.physical_interface.add_ipaddress_to_vlan_interface(interface_id=21, 
                                                                  address='21.21.21.21', 
                                                                  network_value='21.21.21.0/24',
                                                                  vlan_id=21)
        
        # Add another interface to existing 
        engine.physical_interface.add_node_interface(interface_id=22, 
                                                 address='34.34.34.34', 
                                                 network_value='34.34.34.0/24')
        # Add another interface to existing 
        engine.physical_interface.add_node_interface(interface_id=22, 
                                                 address='35.35.35.35', 
                                                 network_value='35.35.35.0/24')
        
        for interface in engine.interface.all():
            if interface.name == 'Interface 21':
                self.assertTrue(interface.address, '21.21.21.21')
                self.assertTrue(interface.network_value, '21.21.21.0/24')
                self.assertIn('21.21', interface.nicid)
            elif interface.name.startswith('Interface 7'):
                self.assertTrue(interface.logical_interface_ref[0].startswith('http'))
                self.assertIn('7.100-8.101', interface.nicid)
                for sub in interface.sub_interfaces():
                    self.assertIsInstance(sub, InlineInterface)
            elif interface.name.startswith('Interface 10'):
                for sub in interface.sub_interfaces():
                    self.assertIsInstance(sub, CaptureInterface)
            elif interface.name == 'Interface 22':
                for sub in interface.sub_interfaces():
                    self.assertIn(sub.address, ['34.34.34.34', '35.35.35.35'])
                    self.assertIn(sub.network_value, ['34.34.34.0/24', '35.35.35.0/24'])
                    
        
        engine.delete()
    
    #@unittest.skip("tmp")  
    def test_layer2_fail_create(self):
        # Catch the create fail exception
        Host.create('smcpython-fw', '1.1.1.1')
        
        with self.assertRaises(CreateEngineFailed):
            Layer2Firewall.create(name='smcpython-fw',
                                  mgmt_ip='1.1.1.1', 
                                  mgmt_network='1.1.1.0/24')
        
        Host('smcpython-fw').delete()   
        
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
        
        engine.physical_interface.add_capture_interface(10, 
                                    logical_interface_ref=logical_intf_helper('Inline'), 
                                    zone_ref=zone_helper('Internal'))
        
        engine.physical_interface.add_inline_interface('11-12', 
                                    logical_interface_ref=logical_intf_helper('default_eth'))
        
        engine.physical_interface.add_vlan_to_inline_interface('5-6', 56, 
                                    logical_interface_ref=logical_intf_helper('default_eth'))
        
        engine.physical_interface.add_vlan_to_inline_interface('5-6', 57, 
                                    logical_interface_ref=logical_intf_helper('default_eth'))
        
        engine.physical_interface.add_vlan_to_inline_interface('5-6', 58, 
                                    logical_interface_ref=logical_intf_helper('default_eth'),
                                    zone_ref_intf1=zone_helper('Internal'),
                                    zone_ref_intf2=zone_helper('DMZ'))
        
        for interface in engine.interface.all():
            if interface.name.startswith('Interface 5'):
                self.assertTrue(interface.has_vlan)
                for sub in interface.vlan_interfaces():
                    self.assertIsInstance(sub, PhysicalVlanInterface)
                    self.assertIn(sub.vlan_id, ['56', '57', '58'])
            elif interface.name.startswith('Interface 11'):
                self.assertTrue(interface.logical_interface_ref[0].startswith('http'))
                self.assertIn('11-12', interface.nicid)
                for sub in interface.sub_interfaces():
                    self.assertIsInstance(sub, InlineInterface)
            elif interface.name.startswith('Interface 10'):
                for sub in interface.sub_interfaces():
                    self.assertIsInstance(sub, CaptureInterface)
        
        engine.delete()
    
    def test_modify_sub_interfaces(self):
        engine = Layer3Firewall.create(name='testfw', 
                                       mgmt_ip='1.1.1.1', 
                                       mgmt_network='1.1.1.0/24')
        self.assertIsInstance(engine, Engine)
        engine.physical_interface.add_single_node_interface(interface_id=1, 
                                                            address='2.2.2.2', 
                                                            network_value='2.2.2.0/24',
                                                            zone_ref=zone_helper('TempZone'))
        engine.physical_interface.add_vlan_to_single_node_interface(interface_id=2, 
                                                                    address='3.3.3.3', 
                                                                    network_value='3.3.3.0/24',
                                                                    vlan_id=3)
        engine.physical_interface.add_vlan_to_node_interface(interface_id=3, 
                                                             vlan_id=4)
        # Test delete fail, cannot delete the management interface without reassigning
        p = engine.physical_interface.get(0)
        self.assertRaises(DeleteElementFailed, lambda: p.delete())
        
        for x in engine.interface.all():
            if x.name == 'Interface 0':
                for y in x.sub_interfaces():
                    y.address = '5.5.5.5'
                    y.network_value = '5.5.5.0/24'
                    self.assertEqual(y.address, '5.5.5.5')
                    self.assertEqual(y.network_value, '5.5.5.0/24')
            elif x.name == 'Interface 1':
                self.assertTrue(x.zone_ref.startswith('http'))
                x.zone_ref = None
                self.assertIsNone(x.zone_ref)
                print('vlans: %s' % x.vlan_interfaces())
                self.assertFalse(x.vlan_interfaces()) #No VLANs
            elif x.name == 'Interface 2':
                self.assertTrue(x.has_vlan)
                self.assertEqual(x.vlan_id[0], '3')
                # Test gettr with VLAN having IP
                for y in x.vlan_interfaces():
                    self.assertIsNone(y.test)
                    y.vlan_id = 10
                    self.assertIsNone(x.save())
                    self.assertEqual(y.vlan_id, '10')
            elif x.name == 'Interface 3':
                for y in x.vlan_interfaces():
                    self.assertEqual(y.vlan_id, '4')
                    self.assertIsNone(y.address)
                # Test getattr
                for y in x.sub_interfaces():
                    self.assertIsNone(y.test)
            
        engine.delete()
                
    #@unittest.skip("tmp")  
    def test_ips_fail_create(self):
        Host.create('smcpython-fw', '1.1.1.1')
        
        with self.assertRaises(CreateEngineFailed):
            IPS.create(name='smcpython-fw', 
                       mgmt_ip='1.1.1.1', 
                       mgmt_network='1.1.1.0/24')
            
        Host('smcpython-fw').delete() 
        
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
        engine.physical_interface.add_cluster_virtual_interface(
                                            interface_id=1,
                                            cluster_virtual='5.5.5.1', 
                                            cluster_mask='5.5.5.0/24', 
                                            macaddress='02:03:03:03:03:03', 
                                            nodes=[{'address':'5.5.5.2', 'network_value':'5.5.5.0/24', 'nodeid':1},
                                                   {'address':'5.5.5.3', 'network_value':'5.5.5.0/24', 'nodeid':2},
                                                   {'address':'5.5.5.4', 'network_value':'5.5.5.0/24', 'nodeid':3}],
                                            zone_ref=zone_helper('Heartbeat'))
        
        for interface in engine.interface.all():
            if interface.name == 'Interface 0':
                self.assertEqual(interface.macaddress, '02:02:02:02:02:02')
                self.assertEqual(['1.1.1.1', '1.1.1.2', '1.1.1.3', '1.1.1.4'], interface.address)
            if interface.name == 'Interface 1':
                self.assertEqual(interface.macaddress, '02:03:03:03:03:03')
                self.assertEqual(['5.5.5.1', '5.5.5.2', '5.5.5.3', '5.5.5.4'], interface.address)
            
        engine.delete()
    
    #@unittest.skip("tmp")  
    def test_firewallcluster_fail_create(self):
        Host.create('smcpython-fw', '1.1.1.1')
        
        with self.assertRaises(CreateEngineFailed):
            FirewallCluster.create(name='smcpython-fw', 
                                   cluster_virtual='1.1.1.1', 
                                   cluster_mask='1.1.1.0/24',
                                   cluster_nic=0,
                                   macaddress='02:02:02:02:02:02',
                                   nodes=[{'address': '1.1.1.2', 'network_value': '1.1.1.0/24', 'nodeid':1},
                                          {'address': '1.1.1.3', 'network_value': '1.1.1.0/24', 'nodeid':2},
                                          {'address': '1.1.1.4', 'network_value': '1.1.1.0/24', 'nodeid':3}],
                                   domain_server_address=['1.1.1.1'], 
                                   zone_ref=zone_helper('Internal'))
        
        Host('smcpython-fw').delete() 
         
    #@unittest.skip("tmp")   
    def testMasterEngine(self):
        
        engine = MasterEngine.create('api-master',
                                     mgmt_ip='1.1.1.1',
                                     mgmt_network='1.1.1.0/24',
                                     master_type='firewall', 
                                     domain_server_address=['8.8.8.8', '7.7.7.7'])
        self.assertIsInstance(engine, Engine)
        engine.physical_interface.add(1)
        engine.physical_interface.add(2)
        engine.physical_interface.add(3)
        
        intf = engine.physical_interface.get(1)
        self.assertFalse(intf.address)
            
        engine.delete()
    
    def test_master_engine_fail_create(self):
        Host.create('smcpython-fw', '1.1.1.1')
        
        with self.assertRaises(CreateEngineFailed):
            MasterEngine.create('smcpython-fw',
                                mgmt_ip='1.1.1.1',
                                mgmt_network='1.1.1.0/24',
                                master_type='firewall', 
                                domain_server_address=['8.8.4.4', '7.7.7.7'])
            
        Host('smcpython-fw').delete() 
        
    def test_masterengine_with_virtual(self):
        #Single master engine, no cluster
        engine = MasterEngine.create('api-master',
                                     mgmt_ip='1.1.1.1',
                                     mgmt_network='1.1.1.0/24',
                                     master_type='firewall', 
                                     domain_server_address=['8.8.4.4', '7.7.7.7'])
        self.assertIsInstance(engine, Engine)
        
        virtual = engine.virtual_resource.create(name='ve-1', vfw_id=1)
        self.assertTrue(virtual.startswith('http'))
        
        engine.physical_interface.add(interface_id=1, virtual_mapping=0,
                                      virtual_resource_name='ve-1')
        
        for interface in engine.interface.all():
            if interface.name == 'Interface 1':
                self.assertEqual(interface.virtual_resource_name, 've-1')
                self.assertEqual(interface.virtual_mapping, 0)
                self.assertIsNone(interface.address)
        
        # Fail due to missing virtual resource
        with self.assertRaises(CreateEngineFailed): 
            Layer3VirtualEngine.create(name='myvirtual', 
                                       master_engine='api-master', 
                                       virtual_resource='foo', 
                                       interfaces=[{'address': '1.1.1.1',
                                                    'network_value': '1.1.1.0/24',
                                                    'interface_id': 0}])

        # Valid virtual resource
        virtualengine = Layer3VirtualEngine.create(
                                    name='myvirtual', 
                                    master_engine='api-master', 
                                    virtual_resource='ve-1', 
                                    interfaces=[{'address': '1.1.1.1',
                                                 'network_value': '1.1.1.0/24',
                                                 'interface_id': 0}])
        
        # Fail creating virtual resource (name already exists)
        with self.assertRaises(CreateEngineFailed): 
            Layer3VirtualEngine.create(name='myvirtual', 
                                       master_engine='api-master', 
                                       virtual_resource='ve-1', 
                                       interfaces=[{'address': '1.1.1.1',
                                                    'network_value': '1.1.1.0/24',
                                                    'interface_id': 0}])
        
        self.assertIsInstance(virtualengine, Engine)
        
        for interface in virtualengine.interface.all():
            self.assertIn('1.1.1.1', interface.address)
            self.assertIn('1.1.1.0/24', interface.network_value)
        
        virtualengine.delete()
        engine.delete()
              
    #@unittest.skip("tmp")
    def testVirtualLayer3Engine(self):
        
        masterengine = MasterEngine.create('api-master',
                                     mgmt_ip='1.1.1.1',
                                     mgmt_network='1.1.1.0/24',
                                     master_type='firewall', 
                                     domain_server_address=['8.8.4.4', '7.7.7.7'])
        
        virtual_resource = masterengine.virtual_resource.create(name='ve-10', vfw_id=1)
        self.assertTrue(virtual_resource.startswith('http'))
        
        masterengine.physical_interface.add_vlan_to_node_interface(interface_id=1, 
                                                                   vlan_id=100, 
                                                                   virtual_mapping=0, 
                                                                   virtual_resource_name='ve-10')
        
        #Master engine must exist and be online or interface will show with red X through it
        engine = Layer3VirtualEngine.create('layer3-ve', 
                                             master_engine='api-master', 
                                             virtual_resource='ve-10',
                                             interfaces=[{'interface_id': 0,
                                                          'address': '1.1.1.1',
                                                          'network_value': '1.1.1.0/24'}])
        self.assertIsInstance(engine, Engine)
        
        for interface in engine.interface.all():
            self.assertEqual(interface.address, ['1.1.1.1'])
            self.assertEqual(interface.network_value, ['1.1.1.0/24'])
        
        engine.delete()
        masterengine.delete()
            
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
        engine.physical_interface.add_cluster_interface_on_master_engine(
                                        interface_id=1,
                                        macaddress='22:22:22:22:22:33', 
                                        nodes=[{'address': '6.6.6.2',
                                                'network_value': '6.6.6.0/24',
                                                'nodeid':1},
                                                {'address':'6.6.6.3',
                                                 'network_value':'6.6.6.0/24',
                                                 'nodeid':2}])
        
        for interface in engine.interface.all():
            if interface.name == 'Interface 0':
                self.assertEqual(interface.macaddress, '22:22:22:22:22:22')
                for addr in interface.address:
                    self.assertIn(addr, ['5.5.5.2', '5.5.5.3'])
                
        #Simulate failed creation of master engine (preexisting with same name)
        with self.assertRaises(CreateEngineFailed):
            MasterEngineCluster.create(name='engine-cluster',
                                       master_type='firewall', 
                                       macaddress='22:22:22:22:22:22', 
                                       nodes=[{'address':'5.5.5.2', 
                                               'network_value':'5.5.5.0/24', 
                                               'nodeid':1},
                                              {'address':'5.5.5.3', 
                                               'network_value':'5.5.5.0/24', 
                                               'nodeid':2}])

        engine.delete()
    
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
        self.assertTrue(result.startswith('http'))
        
        engine.physical_interface.add_vlan_to_node_interface(
                                                        interface_id=1,
                                                        vlan_id=100, 
                                                        virtual_mapping=0, 
                                                        virtual_resource_name='ve-1')
        
        for interface in engine.interface.all():
            if interface.name == 'Interface 0':
                self.assertEqual(interface.macaddress, '22:22:22:22:22:22')
                for addr in interface.address:
                    self.assertIn(addr, ['5.5.5.2', '5.5.5.3'])
            elif interface.name == 'Interface 1':
                for subs in interface.sub_interfaces():
                    self.assertIsInstance(subs, PhysicalVlanInterface)
                    self.assertEqual(subs.virtual_mapping, 0)
                    self.assertEqual(subs.virtual_resource_name, 've-1')

        engine = Layer3VirtualEngine.create('layer3-ve', 
                                            master_engine='engine-cluster', 
                                            virtual_resource='ve-1',
                                            interfaces=[{'interface_id': 0,
                                                         'address': '1.1.1.1',
                                                         'network_value': '1.1.1.0/24'}])
        self.assertIsInstance(engine, Engine)
        
        engine.delete()
        Engine('engine-cluster').load().delete()
       
    def test_tunnel_and_dhcp_interface(self):
        engine = Layer3Firewall.create('myfw', '1.1.1.1', '1.1.1.0/24')
        self.assertIsInstance(engine, Engine)
        
        engine.tunnel_interface.add_single_node_interface(tunnel_id=1000, 
                                                          address='2.2.2.2', 
                                                          network_value='2.2.2.0/24')
        # Add a second interface IP to same tunnel interface
        engine.tunnel_interface.add_single_node_interface(tunnel_id=1000, 
                                                          address='13.13.13.13', 
                                                          network_value='13.13.13.0/24')
        
        engine.physical_interface.add_dhcp_interface(interface_id=20, 
                                                     dynamic_index=1,
                                                     zone_ref=zone_helper('Internal'))
        
        for interface in engine.interface.all():
            if interface.name == 'Tunnel Interface 1000':
                self.assertIsInstance(interface, TunnelInterface)
                for intf in interface.sub_interfaces():
                    self.assertIn(intf.address, ['2.2.2.2', '13.13.13.13'])
                    self.assertIn(intf.network_value, ['2.2.2.0/24', '13.13.13.0/24'])
            elif interface.name == 'Interface 20':
                self.assertEqual(interface.dynamic_index, [1])
                self.assertTrue(interface.zone_ref.startswith('http'))
               
        engine.delete()
    
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
        engine.tunnel_interface.add_cluster_virtual_interface(tunnel_id=1001, 
                                                              address='23.23.23.23', 
                                                              network_value='23.23.23.0/24')
        # Add CVI and NDI (no mac required for Tunnel Interface)
        engine.tunnel_interface.add_cluster_virtual_and_node_interfaces(
                    tunnel_id=1055, 
                    address='77.77.77.77', 
                    network_value='77.77.77.0/24', 
                    nodes=[{'address':'77.77.77.78', 'network_value':'77.77.77.0/24', 'nodeid':1},
                           {'address':'77.77.77.79', 'network_value':'77.77.77.0/24', 'nodeid':2},
                           {'address':'77.77.77.80', 'network_value':'77.77.77.0/24', 'nodeid':3}])
        
        for interface in engine.interface.all():
            if interface.name == 'Interface 0':
                self.assertEqual(interface.macaddress, '02:02:02:02:02:02')
                for address in interface.address:
                    self.assertIn(address, ['1.1.1.1','1.1.1.2','1.1.1.3','1.1.1.4'])
            elif interface.name == 'Tunnel Interface 1001':
                self.assertEqual(interface.address, ['23.23.23.23'])
            elif interface.name == 'Tunnel Interface 1055':
                for intf in interface.address:
                    self.assertIn(intf, ['77.77.77.77', '77.77.77.78', '77.77.77.79', '77.77.77.80'])
    
        engine.delete()
       
    def test_contact_addr_on_physical_and_tunnel(self):
        engine = Layer3Firewall.create('myfw', 
                                       '1.1.1.1', 
                                       '1.1.1.0/24')
        self.assertIsInstance(engine, Engine)
        
        # Add contact address
        for intf in engine.physical_interface.all():
            if intf.name == 'Interface 0':
                self.assertFalse(intf.contact_addresses()) #No contact addresses yet
                address = ContactAddress.create('12.12.12.12') # Default contact address
                intf.add_contact_address(address)
                # Add a second contact address
                address2 = ContactAddress.create('13.13.13.13', location='MyLocation')
                intf.add_contact_address(address2)
                for address in intf.contact_addresses():
                    self.assertIn(address.address, ['12.12.12.12', '13.13.13.13'])
                    self.assertIn(address.location, ['MyLocation', 'Default'])
                    self.assertFalse(address.dynamic)
                
                #Test fail on contact address, cannot add same address twice
                address = ContactAddress.create('12.12.12.12') # Default contact address
                self.assertRaises(EngineCommandFailed, lambda: intf.add_contact_address(address))
                
        engine.delete()
    
if __name__ == "__main__":
    unittest.main()
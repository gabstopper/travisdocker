
import unittest
import inspect
from smc.core.interfaces import PhysicalInterface,\
    _interface_helper, InterfaceFactory
from smc.core.sub_interfaces import NodeInterface, ClusterVirtualInterface,\
    InlineInterface, CaptureInterface, SingleNodeInterface, _add_vlan_to_inline,\
    SubInterface

class TestInterfaces(unittest.TestCase):

    def setUp(self):
        pass
    
    def tearDown(self):
        pass
    
    def test_InterfaceFactory(self):
        # Test the interface factory. Should return the right class given the
        # 'typeof' attribute setting
        import smc.core.interfaces
        for i in [smc.core.interfaces]:# smc.core.sub_interfaces]:
            for _, klazz in inspect.getmembers(i, inspect.isclass):
                if hasattr(klazz, 'typeof'):
                    rc = next(SubInterface.get_subclasses(klazz.typeof))
                    if rc:
                        self.assertEqual(rc, klazz)
                    else:    
                        rc = InterfaceFactory(klazz.typeof)
                        self.assertEqual(rc, klazz)
                    
            
    def test_CviSubInterface(self):
        cvi = ClusterVirtualInterface.create(interface_id=1, 
                                             address='10.0.0.254', 
                                             network_value='10.0.0.0/24',
                                             igmp_mode='upstream')
        
        self.assertEqual(cvi.address, '10.0.0.254')
        self.assertEqual(cvi.network_value, '10.0.0.0/24')
        self.assertEqual(cvi.auth_request, False)
        self.assertEqual(cvi.igmp_mode, 'upstream')
        self.assertEqual(cvi.nicid, 1)
        self.assertEqual(cvi.relayed_by_dhcp, None)
        
        cvi.address = '1.1.1.1'
        cvi.auth_request = True
        cvi.network_value = '1.1.1.0/24'
        cvi.nicid = '2'
        
        self.assertEqual(cvi.address, '1.1.1.1')
        self.assertEqual(cvi.network_value, '1.1.1.0/24')
        self.assertEqual(cvi.auth_request, True)
        self.assertEqual(cvi.nicid, '2')
        self.assertIsNone(cvi.bogus)
        
        called = cvi()
        self.assertIsInstance(called, dict)
        self.assertEqual(called.get(cvi.typeof), cvi.data)
    
    def test_InlineSubInterface(self):
        
        n = InlineInterface.create(interface_id='1-2', 
                                   logical_interface_ref='http://1.1.1.1', 
                                   zone_ref='internal',
                                   failure_mode='normal')
        
        self.assertEqual(n.nicid, '1-2')
        self.assertEqual(n.logical_interface_ref, 'http://1.1.1.1')
        self.assertEqual(n.zone_ref, 'internal')
        self.assertEqual(n.failure_mode, 'normal')
        
        n.inspect_unspecified_vlans = True
        n.logical_interface_ref = 'http://1.1.1.2'
        n.failure_mode = 'normal'
        n.zone_ref = 'external'
        n.virtual_second_mapping = 'noidea'
        n.nicid = '12'
        
        self.assertEqual(n.inspect_unspecified_vlans, True)
        self.assertEqual(n.logical_interface_ref, 'http://1.1.1.2')
        self.assertEqual(n.failure_mode, 'normal')
        self.assertEqual(n.zone_ref, 'external')
        self.assertEqual(n.virtual_second_mapping, 'noidea')
        self.assertEqual(n.nicid, '12')
        self.assertIsNone(n.bogus)
        
        n.nicid = '1.5-2.5'
        self.assertEqual(n.vlan_id, '5')
        n.nicid = '5' #For testing add_vlan_to_inline
        
        called = n()
        self.assertIsInstance(called, dict)
        self.assertEqual(called.get(n.typeof), n.data)
        
        physical = PhysicalInterface()
        physical.add_vlan_to_inline_interface(interface_id='1-2', 
                                              vlan_id=5, 
                                              logical_interface_ref='http://1.1.1.1')
    
        for vlans in physical.data['vlanInterfaces']:
            for interface in vlans['interfaces']:
                for k, v in interface.items():
                    self.assertEqual(k, InlineInterface.typeof)
                    self.assertEqual(v.get('nicid'), '1.5-2.5')
        
        physical = PhysicalInterface()
        physical.add_vlan_to_inline_interface(interface_id='3-4', 
                                              vlan_id=5,
                                              vlan_id2=6, 
                                              logical_interface_ref='http://1.1.1.1')
    
        for vlans in physical.data['vlanInterfaces']:
            for interface in vlans['interfaces']:
                for k, v in interface.items():
                    self.assertEqual(k, InlineInterface.typeof)
                    self.assertEqual(v.get('nicid'), '3.5-4.6')
    
        # This will silently fail and inline interface will not be modified
        self.assertEqual(_add_vlan_to_inline(called, vlan_id=5, vlan_id2=6), called)
        
    def test_CaptureSubInterface(self):
        n = CaptureInterface.create(interface_id=9, 
                                    logical_interface_ref='http://1.1.1.1',
                                    inspect_unspecified_vlans=True)
        
        self.assertEqual(n.nicid, 9)
        self.assertEqual(n.logical_interface_ref, 'http://1.1.1.1')
        self.assertTrue(n.inspect_unspecified_vlans)
        
        n.inspect_unspecified_vlans = True
        n.logical_interface_ref = 'http://1.1.1.2'
        n.reset_interface_nicid = 10
        n.nicid = '10'

        self.assertEqual(n.inspect_unspecified_vlans, True)
        self.assertEqual(n.logical_interface_ref, 'http://1.1.1.2')
        self.assertEqual(n.reset_interface_nicid, 10)
        self.assertEqual(n.nicid, '10')
        self.assertIsNone(n.bogus)
        
        called = n()
        self.assertIsInstance(called, dict)
        self.assertEqual(called.get(n.typeof), n.data)

    def test_NodeSubInterface(self):
        n = NodeInterface.create(interface_id=9, 
                                 address='2.2.2.2', 
                                 network_value='2.2.2.0/24', 
                                 nodeid=3,
                                 backup_for_web_access=True)
        
        self.assertEqual(n.nicid, 9)
        self.assertEqual(n.address, '2.2.2.2')
        self.assertEqual(n.network_value, '2.2.2.0/24')
        self.assertEqual(n.nodeid, 3)
        self.assertTrue(n.backup_for_web_access)
        
        n.address = '1.1.1.1'
        n.network_value = '1.1.1.0/24'
        n.nicid = '10.1'
        n.auth_request = True
        n.auth_request_source = True
        n.backup_mgt = True
        n.dynamic = True
        n.primary_heartbeat = True
        n.backup_heartbeat = True
        n.primary_mgt = True
        n.reverse_connection = True
        n.vrrp = True
        n.vrrp_id = 10
        n.vrrp_address = '1.1.1.1'
        n.vrrp_priority = 10
        n.comment = 'mycomment'
        n.dynamic_index = 10
        n.nodeid = 1
        n.outgoing = True
        
        self.assertEqual(n.igmp_mode, None)
        self.assertEqual(n.pppoa, None)
        self.assertEqual(n.pppoe, None)
        self.assertEqual(n.primary_for_web_access, None)
        self.assertEqual(n.relayed_by_dhcp, None)
        self.assertEqual(n.address, '1.1.1.1')
        self.assertEqual(n.network_value, '1.1.1.0/24')
        self.assertEqual(n.nicid, '10.1')
        self.assertEqual(n.vlan_id, '1')
        self.assertEqual(n.auth_request, True)
        self.assertEqual(n.auth_request_source, True)
        self.assertEqual(n.backup_mgt, True)
        self.assertEqual(n.dynamic, True)
        self.assertEqual(n.primary_heartbeat, True)
        self.assertEqual(n.primary_mgt, True)
        self.assertEqual(n.reverse_connection, True)
        self.assertEqual(n.vrrp, True)
        self.assertEqual(n.vrrp_id, 10)
        self.assertEqual(n.vrrp_address, '1.1.1.1')
        self.assertEqual(n.vrrp_priority, 10)
        self.assertEqual(n.comment, 'mycomment')
        self.assertEqual(n.backup_heartbeat, True)
        self.assertEqual(n.dynamic_index, 10)
        self.assertEqual(n.nodeid, 1)
        self.assertEqual(n.outgoing, True)
        self.assertIsNone(n.bogus)
        
        called = n()
        self.assertIsInstance(called, dict)
        self.assertEqual(called.get(n.typeof), n.data)
        
    def test_SingleNodeSubInterface(self):
        n = SingleNodeInterface.create(interface_id=10, 
                                       address='10.10.10.10', 
                                       network_value='10.10.10.0/24', 
                                       nodeid=10,
                                       automatic_default_route=True)
        self.assertEqual(n.nicid, 10)
        self.assertEqual(n.address, '10.10.10.10')
        self.assertEqual(n.network_value, '10.10.10.0/24')
        self.assertEqual(n.nodeid, 10)
        self.assertTrue(n.automatic_default_route)
        
        n.automatic_default_route = True
        self.assertEqual(n.automatic_default_route, True)
        self.assertIsNone(n.bogus)
        
        called = n()
        self.assertIsInstance(called, dict)
        self.assertEqual(called.get(n.typeof), n.data)
    
    def test_DHCPInterface(self):
        physical = PhysicalInterface()
        physical.add_dhcp_interface(interface_id=10, 
                                    dynamic_index=1, 
                                    primary_mgmt=True, 
                                    zone_ref='http://1.1.1.1')

        self.assertEqual(physical.interface_id, 10)
        self.assertEqual(physical.zone_ref, 'http://1.1.1.1')
        
        intf = _interface_helper(physical.data)
        self.assertTrue(intf.primary_mgt)
        self.assertEqual(intf.nicid, 10)
        self.assertTrue(intf.dynamic)
        self.assertEqual(intf.dynamic_index, 1)
        self.assertEqual(intf.automatic_default_route, True)
        
        intf = SingleNodeInterface.create_dhcp(interface_id=2, dynamic_index=1,
                                               primary_mgt=True)
        self.assertTrue(intf.primary_mgt)
            
    def test_PhysicalInterface(self):
        physical = PhysicalInterface()
        physical.add_single_node_interface(10, address='1.1.1.1', network_value='1.1.1.1', 
                                           zone_ref='http://1.1.1.1/ref', is_mgmt=True)
        physical.aggregate_mode = 'lb'
        physical.comment = 'mycomment'
        physical.cvi_mode = 'unicast'
        physical.macaddress = '0a:0a:0a:0a:0a:0a'
        physical.mtu = 65535
        physical.multicast_ip = '1.1.1.1'
        physical.second_interface_id = 3
        physical.virtual_engine_vlan_ok = True
        physical.virtual_mapping = 15
        physical.virtual_resource_name = 've-1'
        
        self.assertEqual(physical.interface_id, 10)
        self.assertEqual(physical.zone_ref, 'http://1.1.1.1/ref')
        self.assertEqual(physical.aggregate_mode, 'lb')
        self.assertEqual(physical.comment, 'mycomment')
        self.assertEqual(physical.cvi_mode, 'unicast')
        self.assertEqual(physical.macaddress, '0a:0a:0a:0a:0a:0a')
        self.assertEqual(physical.mtu, 65535)
        self.assertEqual(physical.multicast_ip, '1.1.1.1')
        self.assertEqual(physical.second_interface_id, 3)
        self.assertEqual(physical.virtual_engine_vlan_ok, True)
        self.assertEqual(physical.virtual_mapping, 15)
        self.assertEqual(physical.virtual_resource_name, 've-1')
        
        physical.interface_id = 11
        physical.zone_ref = 'http://1.1.1.1/newref'
        self.assertEqual(physical.interface_id, 11)
        self.assertEqual(physical.zone_ref, 'http://1.1.1.1/newref')
        
        
if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
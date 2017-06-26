'''
Created on Jun 25, 2016

@author: davidlepage
'''
import unittest
import mock
import smc.actions.search as search
from smc.tests.constants import url, api_key, verify,\
    is_min_required_smc_version
from smc import session
from smc.compat import min_smc_version
from smc.elements.helpers import zone_helper, logical_intf_helper,\
    location_helper
from smc.core.engines import Layer2Firewall, Layer3Firewall, IPS, FirewallCluster,\
    MasterEngine, Engine, Layer3VirtualEngine, MasterEngineCluster
from smc.api.exceptions import CreateEngineFailed,\
    EngineCommandFailed, CertificateError,\
    UnsupportedEngineFeature, ActionCommandFailed, ElementNotFound,\
    DeleteElementFailed, UpdateElementFailed
from smc.elements.network import Host, Alias, Network, Router
from smc.elements.other import Location
from smc.core.contact_address import InterfaceContactAddress
from smc.core.interfaces import PhysicalInterface,\
    PhysicalVlanInterface, TunnelInterface
from smc.core.sub_interfaces import SingleNodeInterface, CaptureInterface,\
    InlineInterface, ClusterVirtualInterface, NodeInterface
from smc.core.route import Antispoofing
from smc.vpn.elements import VPNCertificate, GatewaySettings
from smc.base.model import lookup_class, SimpleElement
from smc.core.resource import PendingChanges, ChangeRecord
from smc.api.web import SMCResult
from smc.routing.ospf import OSPFProfile
from smc.elements.profiles import DNSRelayProfile
from smc.core.properties import SandboxService
from smc.routing.bgp import AutonomousSystem, BGPProfile
from smc.elements.servers import LogServer
from smc.elements.netlink import StaticNetlink
from smc.elements.group import Group


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
        # First test the raw creation
        engine = Layer3Firewall.create(name='myfw',
                                       mgmt_ip='1.1.1.1',
                                       mgmt_network='1.1.1.0/24',
                                       enable_antivirus=True,
                                       enable_gti=True,
                                       default_nat=True,
                                       location_ref=loc,
                                       sidewinder_proxy_enabled=True,
                                       domain_server_address=['8.8.8.8'])
        
        self.assertIsInstance(engine, Engine)
        
        # Test repr when loading from Engine
        self.assertTrue(repr(engine) == '%s(name=%s)' %
                        (lookup_class(engine.type).__name__, engine.name))

        engine.physical_interface.add_single_node_interface(
            interface_id=120,
            address='120.120.120.100',
            network_value='120.120.120.0/24',
            backup_mgt=True)
        
        itf100 = engine.interface.get(120)
        self.assertTrue(itf100.is_backup_mgt)
        self.assertFalse(itf100.is_primary_heartbeat)
        
        engine.physical_interface.set_backup_mgt(None)
        del itf100.data
        self.assertFalse(itf100.is_backup_mgt)
        
        engine.physical_interface.set_backup_mgt(120)
        del itf100.data
        
        # Load directly
        engine = Layer3Firewall('myfw')

        engine.physical_interface.add_single_node_interface(1, '2.2.2.2', '2.2.2.0/24',
                                                            zone_ref=zone_helper('Internal'))

        engine.physical_interface.add_ipaddress_to_vlan_interface(
            2, '3.3.3.3', '3.3.3.0/24',
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

        # Set management to interface 1 on specific IP
        engine.physical_interface.set_primary_mgt(1, address='22.22.22.22')
        itf = engine.interface.get(1)
        for interface in itf.sub_interfaces():
            if interface.address == '22.22.22.22':
                self.assertTrue(interface.primary_mgt)
                self.assertTrue(interface.outgoing)
                self.assertTrue(interface.auth_request)
        
        engine.physical_interface.set_primary_mgt(0)
        
        # Add empty interface and verify adding IP address afterwards works
        engine.physical_interface.add(20)

        engine.physical_interface.add_single_node_interface(interface_id=20,
                                                            address='11.11.11.11',
                                                            network_value='11.11.11.0/24')

        engine.physical_interface.add_single_node_interface(interface_id=21,
                                                            address='2001:db8:85a3::8a2e:370:7334',
                                                            network_value='2001:db8:85a3::/64')

        # Add this to make sure changing mgmt interfaces doesn't choke 
        engine.physical_interface.add_vlan_to_node_interface(
            interface_id=36, vlan_id=36)
        
        for interface in engine.interface.all():
            if interface.name == 'Interface 1':
                # Retrieve contact address from interface
                self.assertTrue(interface.zone_ref.startswith('http'))
                for sub_intf in interface.sub_interfaces():
                    self.assertIsInstance(sub_intf, SingleNodeInterface)
                    self.assertIn(sub_intf.address, ['2.2.2.2', '22.22.22.22'])
                    self.assertIn(sub_intf.network_value, [
                                  '2.2.2.0/24', '22.22.22.0/24'])
            elif interface.name == 'Interface 2':
                info = interface.addresses
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
                    self.assertEqual(sub_intf.address,
                                     '2001:db8:85a3::8a2e:370:7334')
                    self.assertEqual(sub_intf.network_value,
                                     '2001:db8:85a3::/64')

        # Test getting interfaces
        # Doesn't exist
        self.assertRaises(EngineCommandFailed,
                          lambda: engine.physical_interface.get(10))
        # Existing
        intf = engine.physical_interface.get(0)
        # Can't iterate all from within interface
        self.assertFalse(intf.all())
        
        # Move management
        self.assertTrue(intf.is_primary_mgt)
        del intf.data
        engine.physical_interface.set_primary_mgt(20)
        p = engine.interface.get(20)
        self.assertTrue(p.is_primary_mgt)
        # Intf 0 is no longer primary
        self.assertFalse(intf.is_primary_mgt)
        self.assertFalse(intf.is_backup_mgt)
        
        # Set primary to 0, but auth_request to 20
        engine.physical_interface.set_primary_mgt(0, 20)
        intf = engine.interface.get(0)
        self.assertTrue(intf.is_primary_mgt)
        intf20 = engine.interface.get(20)
        for subintf in intf20.sub_interfaces():
            self.assertTrue(subintf.auth_request)
        
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
        # SubElement __repr__ through UnicodeMixin
        self.assertIsInstance(repr(intf), str)
        self.assertIsInstance(intf, PhysicalInterface)
        self.assertTrue(intf.has_interfaces)
        
        intf.enable_aggregate_mode('lb', [99,100,101,102])
        self.assertEqual(intf.aggregate_mode, 'lb')
        self.assertEqual(intf.second_interface_id, '99,100,101,102')
        
        # Invalid, aggregate mode values are 'lb' and 'ha'.
        intf.enable_aggregate_mode('foo', [])
        self.assertEqual(intf.aggregate_mode, 'lb')
        
        intf.change_single_ipaddress(address='101.101.101.101',
                                    network_value='101.101.101.0/24')
        for itf in intf.sub_interfaces():
            self.assertEqual(itf.address, '101.101.101.101')
        
        # Add a physical interface with a single VLAN, no IP Address
        engine.physical_interface.add_vlan_to_node_interface(interface_id=21,
                                                             vlan_id=20)
        # Verify that a PhysicalVlanInterface type is returned
        for x in engine.interface.all():
            if x.name == 'Interface 21':
                for vlan in x.sub_interfaces():
                    self.assertIsInstance(vlan, PhysicalVlanInterface)
                    # VLAN cannot not have nested VLANs
                    self.assertFalse(vlan.has_vlan)

        # Now add the IP Address to the VLAN interface
        engine.physical_interface.add_ipaddress_to_vlan_interface(21, 
                                                                  address='21.21.21.21',
                                                                  network_value='21.21.21.0/24',
                                                                  vlan_id=20)
        # Second IP on same VLAN
        engine.physical_interface.add_ipaddress_to_vlan_interface(21, 
                                                                  address='31.31.31.31',
                                                                  network_value='31.31.31.0/24',
                                                                  vlan_id=20)
        
        engine.physical_interface.add_ipaddress_to_vlan_interface(21, 
                                                                  address='22.21.21.21',
                                                                  network_value='22.21.21.0/24',
                                                                  vlan_id=21)
        engine.physical_interface.add_ipaddress_to_vlan_interface(21, 
                                                                  address='23.21.21.21',
                                                                  network_value='23.21.21.0/24',
                                                                  vlan_id=22)
        
        # Management to single IP on VLAN interface with multiple IPs
        engine.physical_interface.set_primary_mgt('21.20', address='31.31.31.31')
        itf = engine.physical_interface.get(21)
        for sub in itf.sub_interfaces():
            if sub.address == '31.31.31.31':
                self.assertTrue(sub.auth_request)
                self.assertTrue(sub.primary_mgt)
                self.assertTrue(sub.outgoing)
        
        # Test add management on multi-VLAN interface
        engine.physical_interface.set_primary_mgt('21.21')
        itf = engine.interface.get(21)
        self.assertTrue(itf.is_primary_mgt)
        
        engine.physical_interface.set_outgoing(0)
        itf = engine.physical_interface.get(0)
        self.assertTrue(itf.is_outgoing)
    
        # Set primary to one VLAN and auth_request to another. Generally not really
        # common, but our update method allows it. The reason for this is that when
        # setting primary management, if this is done on a cluster with no CVI, you
        # cannot also set the auth request to that interface.
        engine.physical_interface.set_primary_mgt('21.20', '21.22',
                                                  address='21.21.21.21')
        itf = engine.physical_interface.get(21)
        for subs in itf.sub_interfaces():
            if subs.vlan_id == '22':
                self.assertTrue(subs.auth_request)
            elif subs.vlan_id == '20':
                if subs.address == '21.21.21.21':
                    self.assertTrue(subs.primary_mgt)
                else:
                    self.assertFalse(subs.primary_mgt)
    
        # Change only single IP on multiple IP address interface (in VLANs)
        itf.change_single_ipaddress('222.222.222.222', '222.222.222.0/24',
                                    replace_ip='22.21.21.21')
        for intf in itf.sub_interfaces():
            if intf.vlan_id == '21':
                self.assertEqual(intf.address, '222.222.222.222')
            
        # The interface does not exist!
        with self.assertRaises(EngineCommandFailed):
            engine.physical_interface.add_ipaddress_to_vlan_interface(25, address='21.21.21.21',
                                                                      network_value='21.21.21.0/24',
                                                                      vlan_id=20)

        # Add Tunnel interfaces
        engine.tunnel_interface.add_single_node_interface(tunnel_id=1000,
                                                          address='100.100.100.100',
                                                          network_value='100.100.100.0/24',
                                                          zone_ref=zone_helper('blahfoo'))

        # Add another IP to this Tunnel
        engine.tunnel_interface.add_single_node_interface(tunnel_id=1000,
                                                          address='110.110.110.110',
                                                          network_value='110.110.110.0/24')

        engine.physical_interface.add(50)  # Interface with no addresses
        for x in engine.interface.all():
            if x.name == 'Interface 50':
                self.assertFalse(x.interfaces)  # Empty List
            if x.name == 'Tunnel Interface 1000':
                self.assertTrue(x.zone_ref.startswith('http'))

        # Add ARP Entry to interface 0 and verify
        interface = engine.physical_interface.get(0)
        interface.add_arp_entry(ipaddress='23.23.23.23',
                                macaddress='02:02:02:02:02:04')
        interface.save()

        for arp_entry in interface.arp_entry:
            self.assertEqual(arp_entry.get('ipaddress'), '23.23.23.23')
            self.assertEqual(arp_entry.get('macaddress'), '02:02:02:02:02:04')
            self.assertEqual(arp_entry.get('netmask'), 32)

        # Check VPN status....
        for vpn in engine.internal_gateway.internal_endpoint:
            if vpn.name == '2.2.2.2':
                # Modify these attributes
                vpn.modify_attribute(enabled=True,
                                     nat_t=True,
                                     force_nat_t=True,
                                     ssl_vpn_portal=False,
                                     ssl_vpn_tunnel=True,
                                     ipsec_vpn=True)
                self.assertTrue(vpn.enabled)
                self.assertTrue(vpn.nat_t)
                self.assertTrue(vpn.force_nat_t)
                self.assertFalse(vpn.ssl_vpn_portal)
                self.assertTrue(vpn.ssl_vpn_tunnel)
                self.assertTrue(vpn.ipsec_vpn)
                
        # Get aliases
        aliases = engine.alias_resolving()
        for alias in aliases:
            self.assertIsInstance(alias, Alias)
            self.assertIsNotNone(alias.name)
            self.assertTrue(alias.href.startswith('http'))
            self.assertIsInstance(alias.resolved_value, list)

        # Resolve the IP address alias for this engine
        alias = Alias('$$ Interface ID 0.ip')
        self.assertIn('1.1.1.1', alias.resolve('myfw'))

        # Antispoofing
        Network.create(name='network-10.1.2.0/24', ipv4_network='10.1.2.0/24')
        spoofing = engine.antispoofing
        self.assertIsInstance(spoofing, Antispoofing)
        for entry in engine.antispoofing.all():
            if entry.name == 'Interface 0':
                self.assertEqual(entry.level, 'interface')
                self.assertEqual(entry.validity, 'enable')
                entry.add(Network('network-10.1.2.0/24'))

        # Look for our network
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

        # Compare engine ETAG to make sure it's current with SMC
        server_etag = search.element_by_href_as_smcresult(engine.href).etag
        self.assertEqual(engine.etag, server_etag)

        # Gen certificate for internal gateway, fail because engine can't gen
        # cert when uninitialized
        v = VPNCertificate('myorg', 'foo.org')
        self.assertRaises(
            CertificateError, lambda: engine.internal_gateway.generate_certificate(v))

        # Modify an attribute on engine using lower level modify_attribute
        # Requires key value. Replaces full nested dict in this case.
        response = engine.modify_attribute(scan_detection={'scan_detection_icmp_events': 250,
                                                           'scan_detection_icmp_timewindow': 1,
                                                           'scan_detection_tcp_events': 220,
                                                           'scan_detection_tcp_timewindow': 1,
                                                           'scan_detection_type': 'default off',
                                                           'scan_detection_udp_events': 220,
                                                           'scan_detection_udp_timewindow': 1})
        self.assertTrue(response.startswith('http'))
        result = engine.scan_detection
        self.assertEqual(result.get('scan_detection_icmp_events'), 250)

        # Pending changes, only supported in version 6.2
        if min_smc_version(6.2):
            pending_changes = engine.pending_changes
            self.assertIsInstance(pending_changes, PendingChanges)
            self.assertFalse(pending_changes.has_changes)
            # Not enabled on global system properties
            with self.assertRaises(ActionCommandFailed):
                pending_changes.approve_all_changes()
            with self.assertRaises(ActionCommandFailed):
                pending_changes.disapprove_all_changes()
            engine.data['link'] = [x for x in engine.data['link']
                                   if x.get('rel') != 'pending_changes']
            #del engine._resource.pending_changes
            with self.assertRaises(UnsupportedEngineFeature):
                engine.pending_changes
        else:
            with self.assertRaises(UnsupportedEngineFeature):
                engine.pending_changes

        export = engine.export(filename='export.zip').wait()
        self.assertTrue(export.success)

        # Test DNS Servers
        engine.add_dns_servers(['3.3.3.3', '4.4.4.4'])
        for server in engine.dns_servers:
            self.assertIn(server, ['3.3.3.3', '4.4.4.4', '8.8.8.8'])

        # Test DNS Relay
        if is_min_required_smc_version('6.2.0'):
            self.assertFalse(engine.is_dns_relay_enabled)
            engine.enable_dns_relay(interface_id=0)
            self.assertTrue(engine.is_dns_relay_enabled)
            engine.disable_dns_relay()
            self.assertFalse(engine.is_dns_relay_enabled)

        # Try DNS Relay as str
        profile = DNSRelayProfile('Cache Only')  # system default
        engine.enable_dns_relay(interface_id=0, dns_relay_profile=profile.href)
        engine.update()
        self.assertTrue(engine.is_dns_relay_enabled)

        # Simulate version pre-6.2 by removing dns_relay_interface attribute
        engine.data.pop('dns_relay_interface')
        with self.assertRaises(UnsupportedEngineFeature):
            engine.disable_dns_relay()
            # Add attribute back
            engine.data['dns_relay_interface'] = []

        # Sidewinder Proxy Enable/Disable
        self.assertTrue(engine.is_sidewinder_proxy_enabled)
        engine.disable_sidewinder_proxy()
        engine.update()
        self.assertFalse(engine.is_sidewinder_proxy_enabled)
        engine.enable_sidewinder_proxy()
        engine.update()
        self.assertTrue(engine.is_sidewinder_proxy_enabled)
        # Simulate pre-version 6.1 by removing the sidewinder_proxy attribute
        engine.data.pop('sidewinder_proxy_enabled')
        with self.assertRaises(UnsupportedEngineFeature):
            engine.enable_sidewinder_proxy()

        # Test GTI
        # GTI was enabled on the engine creation
        session.AUTOCOMMIT = True
        self.assertTrue(engine.is_gti_enabled)
        engine.disable_gti_file_reputation() # Enabled due to autocommit
        session.AUTOCOMMIT = False
        self.assertFalse(engine.is_gti_enabled)
        engine.enable_gti_file_reputation()
        engine.update()
        self.assertTrue(engine.is_gti_enabled)

        # Test AV
        self.assertTrue(engine.is_antivirus_enabled)
        engine.disable_antivirus()
        engine.update()
        self.assertFalse(engine.is_antivirus_enabled)
        engine.enable_antivirus()
        engine.update()
        self.assertTrue(engine.is_antivirus_enabled)

        # Test OSPF
        self.assertFalse(engine.is_ospf_enabled)
        engine.enable_ospf()
        engine.update()
        self.assertTrue(engine.is_ospf_enabled)
        engine.disable_ospf()
        engine.update()
        self.assertFalse(engine.is_ospf_enabled)

        ospf = OSPFProfile('Default OSPFv2 Profile')
        # Provide OSPFProfile as href
        engine.enable_ospf(ospf_profile=ospf.href)
        engine.update()
        self.assertTrue(engine.is_ospf_enabled)

        # Simulate trying to enable dynamic routing on a non-layer3 engine
        engine.data.pop('dynamic_routing')
        with self.assertRaises(UnsupportedEngineFeature):
            engine.enable_ospf()

        # Default NAT
        self.assertTrue(engine.is_default_nat_enabled)
        engine.disable_default_nat()
        engine.update()
        self.assertFalse(engine.is_default_nat_enabled)
        engine.enable_default_nat()
        engine.update()
        self.assertTrue(engine.is_default_nat_enabled)

        # Simulate no NAT due to specific engine type (i.e. IPS)
        engine.data.pop('default_nat')
        with self.assertRaises(UnsupportedEngineFeature):
            engine.disable_default_nat()
            engine.data['default_nat'] = True  # Reset

        # Test sandbox
        self.assertFalse(engine.is_sandbox_enabled)
        engine.enable_sandbox(license_key='123456', license_token='abcdef')
        engine.update()
        self.assertTrue(engine.is_sandbox_enabled)
        engine.disable_sandbox()
        engine.update()
        self.assertFalse(engine.is_sandbox_enabled)
        engine.enable_sandbox(license_key='123456', license_token='abcdef',
                              service=SandboxService('Automatic'))
        engine.update()
        self.assertTrue(engine.is_sandbox_enabled)

        # URL Filtering
        self.assertFalse(engine.is_url_filtering_enabled)
        engine.enable_url_filtering()
        engine.update()
        self.assertTrue(engine.is_url_filtering_enabled)
        engine.disable_url_filtering()
        engine.update()
        self.assertFalse(engine.is_url_filtering_enabled)

        # BGP
        Network.create(name='bgpnet', ipv4_network='1.1.1.0/24')
        self.assertFalse(engine.is_bgp_enabled)
        AutonomousSystem.create(name='myas', as_number=100)
        engine.enable_bgp(autonomous_system=AutonomousSystem('myas'),
                          announced_networks=[Network('bgpnet')],
                          bgp_profile=BGPProfile('Default BGP Profile'))
        engine.update()
        self.assertTrue(engine.is_bgp_enabled)
        engine.disable_bgp()
        engine.update()
        self.assertFalse(engine.is_bgp_enabled)

        # Test Location getting and setting
        self.assertEqual(engine.location.name, 'anapilocation')
        Location.create('templocation')
        engine.set_location(Location('templocation'))
        engine.update()
        self.assertEqual(engine.location.name, 'templocation')
        engine.set_location(None)
        engine.update()
        self.assertEqual(engine.location.name, 'Default')

        # Log Server
        log_server = engine.log_server
        self.assertIsInstance(log_server, LogServer)

        # Gateway settings, only available on Layer 3 FW
        # <-- temporary - initial engine does not display this attr in 6.2
        gw = list(GatewaySettings.objects.all())
        engine.modify_attribute(gateway_settings_ref=gw[0].href)
        gw_setting = engine.gateway_setting_profile
        self.assertIsInstance(gw_setting, GatewaySettings)

        # Add a VPN Site to this engine
        site_href = engine.add_vpn_site(
            name='mysite', 
            site_elements=[Network('bgpnet')])
        self.assertTrue(site_href.startswith('http'))
        
        for x in engine.internal_gateway.vpn_site.all():
            if x.name == 'mysite':
                for site_elements in x.site_element:
                    self.assertIn(site_elements.name, ['bgpnet'])

        Router.create(name='nexthoprtr', address='1.1.1.100')
        Group.create(name='routegroup',
                     members=[Network.create(name='routenet', ipv4_network='192.168.1.0/24')])
        
        #engine.physical_interface.set_primary_mgt(0)
        route = engine.routing.get(0)

        route.add_static_route(gateway=Router('nexthoprtr'),
                               destination=[Group('routegroup')])
        for routes in route:
            for nexthops in routes:
                self.assertEqual(nexthops.name, 'nexthoprtr')
                for dest in nexthops:
                    self.assertEqual(dest.name, 'routegroup')
        
        # Change the interface ID
        itf = engine.physical_interface.get(0)
        itf.change_interface_id(100)
        self.assertTrue(itf.interface_id, 100)
        
        itf = engine.physical_interface.get(21)
        itf.change_vlan_id(22, 32)
        for interface in itf.vlan_interfaces():
            for physicalvlan in interface.interfaces:
                if physicalvlan.address == '23.21.21.21':
                    self.assertEqual(physicalvlan.vlan_id, '32')
        
        # One VLAN multiple IP's
        itf.change_vlan_id(20, 200)
        for interface in itf.vlan_interfaces():
            for physicalvlan in interface.interfaces:
                if physicalvlan.address in ['21.21.21.21', '31.31.31.31']:
                    self.assertEqual(physicalvlan.vlan_id, '200')
        
        engine.physical_interface.set_primary_mgt(100)
        
        itf = engine.physical_interface.get(21)
        
        # Test delete inteface 21 with multiple VLANs. Also removes routing table entries
        itf.delete()
        for routes in engine.routing:
            self.assertFalse(routes.name.startswith('VLAN 21.'))
        
        engine.delete()
        Network('network-10.1.2.0/24').delete()
        Network('bgpnet').delete()
        AutonomousSystem('myas').delete()
    
    @mock.patch('smc.api.common.SMCRequest.read')
    def test_pending_changes(self, mock_request):
        b = {'link': [{'href': 'http://1.1.1.1',
                   'rel': 'pending_changes'}]}
        class MockEngine(object):
            def __init__(self):
                self.data = SimpleElement(**b)

        engine = MockEngine()
        engine._resource = 'http://1.1.1.1'

        result = SMCResult()
        result.href = result.msg = None
        result.json = [{'modifier': 'admin',
                        'changed_on': '2017-03-16 20:41:07 (GMT)',
                        'event_type': 'stonegate.object.update',
                        'element': 'http://1.1.1.1:8082/6.2/elements/single_fw/659',
                        'approved_on': ''}]
        mock_request.return_value = result

        pending_changes = PendingChanges(engine)
        for record in pending_changes.pending_changes():
            self.assertIsInstance(record, ChangeRecord)
        self.assertTrue(pending_changes.has_changes)
    
    @mock.patch('smc.api.common.SMCRequest.create')
    def test_approve_disapprove_pending_changes(self, mock_request):
        b = {'link': [{'href': 'http://1.1.1.1',
                       'rel': 'approve_all_changes'},
                      {'href': 'http://1.1.1.1',
                       'rel': 'disapprove_all_changes'}]}
        class MockEngine(object):
            def __init__(self):
                self.data = SimpleElement(**b)

        engine = MockEngine()
        #engine.resource = 'http://1.1.1.1'
        #engine.resource.get_link('approve_all_changes') = 'http://1.1.1.1'
        #engine.resource.get_link('disapprove_all_changes') = 'http://1.1.1.1'

        result = SMCResult()
        result.href = result.msg = None
        mock_request.return_value = result

        pending_changes = PendingChanges(engine)
        self.assertIsNone(pending_changes.approve_all_changes())
        self.assertIsNone(pending_changes.disapprove_all_changes())

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
        # Test repr
        self.assertTrue(repr(engine) == '%s(name=%s)' %
                        (lookup_class(engine.type).__name__, engine.name))

        # Load directly
        engine = Layer2Firewall('l2')
        engine.physical_interface.add_capture_interface(10,
                                                        logical_interface_ref=logical_intf_helper(
                                                            'Inline'),
                                                        zone_ref=zone_helper('Internal'))

        engine.physical_interface.add_inline_interface(interface_id='11-12',
                                                       logical_interface_ref=logical_intf_helper('default_eth'))

        engine.physical_interface.add_vlan_to_inline_interface('5-6', 56,
                                                               logical_interface_ref=logical_intf_helper('default_eth'))

        engine.physical_interface.add_vlan_to_inline_interface('5-6', 57,
                                                               logical_interface_ref=logical_intf_helper('default_eth'))

        engine.physical_interface.add_vlan_to_inline_interface('5-6', 58,
                                                               logical_interface_ref=logical_intf_helper(
                                                                   'default_eth'),
                                                               zone_ref_intf1=zone_helper(
                                                                   'Internal'),
                                                               zone_ref_intf2=zone_helper('DMZ'))

        engine.physical_interface.add_vlan_to_inline_interface('7-8', vlan_id=100, vlan_id2=101,
                                                               logical_interface_ref=logical_intf_helper('default_eth'))

        # Add a layer 3 node interface with VLAN, no address
        engine.physical_interface.add_vlan_to_node_interface(
            interface_id=21, vlan_id=21)

        # Add the IP address to this VLAN
        engine.physical_interface.add_ipaddress_to_vlan_interface(interface_id=21,
                                                                  address='21.21.21.21',
                                                                  network_value='21.21.21.0/24',
                                                                  vlan_id=21)

        # Add another interface to existing
        engine.physical_interface.add_node_interface(interface_id=22,
                                                     address='34.34.34.34',
                                                     network_value='34.34.34.0/24',
                                                     zone_ref=zone_helper('tmpzone'))
        # Add another interface to existing
        engine.physical_interface.add_node_interface(interface_id=22,
                                                     address='35.35.35.35',
                                                     network_value='35.35.35.0/24')

        for interface in engine.interface.all():
            if interface.name == 'Interface 21':
                address, network, nicid = interface.addresses[0]
                self.assertTrue(address, '21.21.21.21')
                self.assertTrue(network, '21.21.21.0/24')
                self.assertTrue(nicid, '21.21')
                # Test address attribute on PhysicalVlanInterface repr
                for vlanif in interface.vlan_interfaces():
                    self.assertEqual(vlanif.address, '21.21.21.21')
            elif interface.name.startswith('Interface 7'):
                for sub in interface.sub_interfaces():
                    self.assertIsInstance(sub, InlineInterface)
                    self.assertTrue(
                        sub.logical_interface_ref.startswith('http'))
            elif interface.name.startswith('Interface 10'):
                for sub in interface.sub_interfaces():
                    self.assertIsInstance(sub, CaptureInterface)
            elif interface.name == 'Interface 22':
                for sub in interface.sub_interfaces():
                    self.assertIn(sub.address, ['34.34.34.34', '35.35.35.35'])
                    self.assertIn(sub.network_value, [
                                  '34.34.34.0/24', '35.35.35.0/24'])
                self.assertTrue(interface.zone_ref.startswith('http'))

        # Get an inline interface directly
        interface = engine.interface.get(8)
        self.assertIsInstance(interface, PhysicalInterface)

        # BGP fails on IPS/Layer2
        with self.assertRaises(UnsupportedEngineFeature):
            engine.enable_bgp(autonomous_system='foo',
                              announced_networks=['foo'])

        with self.assertRaises(UnsupportedEngineFeature):
            engine.enable_ospf()

        # Gateway settings not available on layer 3 or IPS
        gw_setting = engine.gateway_setting_profile
        self.assertIsNone(gw_setting)

        itf = engine.interface.get(21)
        self.assertFalse(itf.is_primary_mgt)
        itf.set_primary_mgt('21.21')
        self.assertTrue(itf.is_primary_mgt)
        
        itf = engine.interface.get('5-6')
        itf.change_interface_id('50-60')
        self.assertTrue(itf.interface_id, 50)

        for x in itf.sub_interfaces():
            intfs = x.nicid.split('-')
            self.assertEqual(intfs[0], '50')
            self.assertEqual(intfs[1], '60')
        for physicalvlan in itf.vlan_interfaces():
            self.assertIsNone(physicalvlan.address)
            for sub_intf in physicalvlan.sub_interfaces():
                nics = sub_intf.nicid.split('-')
                self.assertIn(nics[0], ['50.57', '50.56', '50.58'])
                self.assertIn(nics[1], ['60.57', '60.56', '60.58'])
        
        itf = engine.interface.get(7)
        # Change when two interfaces have different VLANs
        itf.change_vlan_id('100-101', '200-201')
        for vlan in itf.vlan_interfaces():
            for interface in vlan.interfaces:
                ids = interface.vlan_id.split('-')
                self.assertIn('200', ids)
                self.assertIn('201', ids)
                
        # Now change to single VLAN on interface pair
        itf.change_vlan_id('200-201', 100)
        for vlan in itf.vlan_interfaces():
            for interface in vlan.interfaces:
                self.assertEqual(interface.vlan_id, '100')
                
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
        # Test repr
        self.assertTrue(repr(engine) == '%s(name=%s)' %
                        (lookup_class(engine.type).__name__, engine.name))

        # Load directly
        engine = IPS('ips')

        engine.physical_interface.add_capture_interface(10,
                                                        logical_interface_ref=logical_intf_helper(
                                                            'Inline'),
                                                        zone_ref=zone_helper('Internal'))

        engine.physical_interface.add_inline_interface('11-12',
                                                       logical_interface_ref=logical_intf_helper('default_eth'))

        engine.physical_interface.add_vlan_to_inline_interface('5-6', 56,
                                                               logical_interface_ref=logical_intf_helper('default_eth'))

        engine.physical_interface.add_vlan_to_inline_interface('5-6', 57,
                                                               logical_interface_ref=logical_intf_helper('default_eth'))

        engine.physical_interface.add_vlan_to_inline_interface('5-6', 58,
                                                               logical_interface_ref=logical_intf_helper(
                                                                   'default_eth'),
                                                               zone_ref_intf1=zone_helper(
                                                                   'Internal'),
                                                               zone_ref_intf2=zone_helper('DMZ'))
        
        engine.physical_interface.add_vlan_to_inline_interface(
            interface_id='7-8', 
            vlan_id=200, 
            vlan_id2=201, 
            logical_interface_ref=logical_intf_helper('default_eth'))

        for interface in engine.interface.all():
            if interface.name.startswith('Interface 5'):
                self.assertTrue(interface.has_vlan)
                for sub in interface.vlan_interfaces():
                    self.assertIsInstance(sub, PhysicalVlanInterface)
                    self.assertIn(sub.vlan_id, ['56', '57', '58'])
            elif interface.name.startswith('Interface 11'):
                for sub in interface.sub_interfaces():
                    self.assertIsInstance(sub, InlineInterface)
                    self.assertTrue(
                        sub.logical_interface_ref.startswith('http'))
                    self.assertEqual(sub.nicid, '11-12')
            elif interface.name.startswith('Interface 10'):
                for sub in interface.sub_interfaces():
                    self.assertIsInstance(sub, CaptureInterface)

        # Change IP address of '7-8' to '77-88' (two unique VLAN id's
        itf = engine.interface.get(7)
        itf.change_interface_id('77-88')
        for interface in itf.sub_interfaces():
            self.assertEqual(interface.nicid, '77-88')
        for interface in itf.vlan_interfaces():
            for vlan in interface.vlan_id.split('-'):
                self.assertIn(vlan, ['200','201'])
        
        # BGP fails on IPS/Layer2
        with self.assertRaises(UnsupportedEngineFeature):
            engine.enable_bgp(autonomous_system='foo',
                              announced_networks=['foo'])

        with self.assertRaises(UnsupportedEngineFeature):
            engine.enable_ospf()

        # Gateway settings not available on layer 3 or IPS
        gw_setting = engine.gateway_setting_profile
        self.assertIsNone(gw_setting)

        itf = engine.interface.get(5)
        itf.change_vlan_id(58, 88)
        for vlan in itf.vlan_interfaces():
            self.assertIn(vlan.vlan_id, ['56', '57', '88'])
            
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

        engine.physical_interface.add_ipaddress_to_vlan_interface(interface_id=2,
                                                                  address='3.3.3.3',
                                                                  network_value='3.3.3.0/24',
                                                                  vlan_id=3)

        engine.physical_interface.add_vlan_to_node_interface(interface_id=3,
                                                             vlan_id=4)
        # Test delete fail, cannot delete the management interface without
        # reassigning
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
                self.assertFalse(x.vlan_interfaces())  # No VLANs
            elif x.name == 'Interface 2':
                self.assertTrue(x.has_vlan)
                for vlan in x.sub_interfaces():
                    self.assertEqual(vlan.vlan_id, '3')

            elif x.name == 'Interface 3':
                for y in x.vlan_interfaces():
                    self.assertEqual(y.vlan_id, '4')
                    self.assertIsNone(y.address)
                # Test getattr
                with self.assertRaises(AttributeError):
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
        # not found node in SMC
        with self.assertRaises(ElementNotFound):
            Engine('ergergserger').href

    #@unittest.skip("tmp")
    def testFirewallCluster(self):

        engine = FirewallCluster.create(name='mycluster',
                                        cluster_virtual='1.1.1.1',
                                        cluster_mask='1.1.1.0/24',
                                        cluster_nic=0,
                                        macaddress='02:02:02:02:02:02',
                                        nodes=[{'address': '1.1.1.2', 'network_value': '1.1.1.0/24', 'nodeid': 1},
                                               {'address': '1.1.1.3',
                                                'network_value': '1.1.1.0/24', 'nodeid': 2},
                                               {'address': '1.1.1.4', 'network_value': '1.1.1.0/24', 'nodeid': 3}],
                                        domain_server_address=['1.1.1.1'],
                                        zone_ref=zone_helper('Internal'))
    
        self.assertIsInstance(engine, Engine)
        itf = engine.interface.get(0)
        self.assertTrue(itf.is_primary_heartbeat)
        
        # Test repr
        self.assertTrue(repr(engine) == '%s(name=%s)' %
                        (lookup_class(engine.type).__name__, engine.name))
        
        # Load directly
        engine = FirewallCluster('mycluster')
        engine.physical_interface.add_cluster_virtual_interface(
            interface_id=1,
            cluster_virtual='5.5.5.1',
            cluster_mask='5.5.5.0/24',
            macaddress='02:03:03:03:03:03',
            nodes=[{'address': '5.5.5.2', 'network_value': '5.5.5.0/24', 'nodeid': 1},
                   {'address': '5.5.5.3',
                    'network_value': '5.5.5.0/24', 'nodeid': 2},
                   {'address': '5.5.5.4', 'network_value': '5.5.5.0/24', 'nodeid': 3}],
            zone_ref=zone_helper('Heartbeat'),
            backup_mgt=True)
        
        itf = engine.interface.get(1)
        self.assertFalse(itf.is_primary_heartbeat)
        self.assertFalse(itf.is_backup_heartbeat)

        engine.physical_interface.set_backup_heartbeat(1)
        itf = engine.interface.get(1)
        self.assertTrue(itf.is_backup_heartbeat)
        engine.physical_interface.set_backup_heartbeat(None)
        engine.physical_interface.set_primary_heartbeat(1)
        itf = engine.interface.get(1)
        self.assertTrue(itf.is_primary_heartbeat)
        
        for interface in engine.interface.all():
            if interface.name == 'Interface 0':
                self.assertEqual(interface.macaddress, '02:02:02:02:02:02')
                for intf in interface.addresses:
                    address, _, _ = intf
                    self.assertIn(
                        address, ['1.1.1.1', '1.1.1.2', '1.1.1.3', '1.1.1.4'])
            if interface.name == 'Interface 1':
                self.assertEqual(interface.macaddress, '02:03:03:03:03:03')
                self.assertTrue(interface.zone_ref.startswith('http'))
                for sub in interface.sub_interfaces():
                    if isinstance(sub, NodeInterface):
                        self.assertTrue(sub.backup_mgt)
                        sub.backup_mgt = False #Reset to False
                    self.assertIn(
                        sub.address, ['5.5.5.1', '5.5.5.2', '5.5.5.3', '5.5.5.4'])
                interface.save()
                
        # Move management
        intf = engine.interface.get(0)
        self.assertTrue(intf.is_primary_mgt)
        del intf.data
        engine.physical_interface.set_primary_mgt(1)
        eth1 = engine.interface.get(1)
        self.assertTrue(eth1.is_primary_mgt)
        self.assertFalse(intf.is_primary_mgt)
        
        engine.physical_interface.add_cluster_virtual_interface(
            interface_id=1,
            cluster_virtual='6.6.6.1',
            cluster_mask='6.6.6.0/24',
            macaddress='02:03:03:03:03:04',
            nodes=[{'address': '6.6.6.2', 'network_value': '6.6.6.0/24', 'nodeid': 1},
                   {'address': '6.6.6.3', 'network_value': '6.6.6.0/24', 'nodeid': 2},
                   {'address': '6.6.6.4', 'network_value': '6.6.6.0/24', 'nodeid': 3}])
        
        engine.physical_interface.set_primary_mgt(interface_id=1,
                                                  address='6.6.6.1')
       
        itf = engine.interface.get(1)
        for sub in itf.sub_interfaces():
            if isinstance(sub, ClusterVirtualInterface) and sub.address == '6.6.6.1':
                self.assertTrue(sub.auth_request)
            if isinstance(sub, NodeInterface):
                if sub.network_value in ['6.6.6.2', '6.6.6.3', '6.6.6.4']:
                    self.assertTrue(sub.primary_mgt)
        
        # Change addresses on interface 1
        itf = engine.interface.get(0)
        itf.change_cluster_ipaddress(
            cvi='7.7.7.1',
            cvi_network_value='7.7.7.0/24',
            nodes=[{'address': '7.7.7.2', 'network_value': '7.7.7.0/24', 'nodeid': 1},
                   {'address': '7.7.7.3', 'network_value': '7.7.7.0/24', 'nodeid': 2},
                   {'address': '7.7.7.4', 'network_value': '7.7.7.0/24', 'nodeid': 3}])
        for sub in itf.sub_interfaces():
            self.assertIn(sub.address, ['7.7.7.1', '7.7.7.2', '7.7.7.3', '7.7.7.4'])           
        
        # CVI only
        engine.physical_interface.add_cluster_virtual_interface(
            interface_id=30,
            cluster_virtual='30.30.30.1',
            cluster_mask='30.30.30.0/24', 
            macaddress='02:02:02:02:02:06')
        
        # Change this CVI
        itf = engine.physical_interface.get(30)
        itf.change_cluster_ipaddress(cvi='30.30.30.254')
        for sub in itf.sub_interfaces():
            self.assertEqual(sub.address, '30.30.30.254')
        
        itf.change_cluster_ipaddress(cvi='31.31.31.254', cvi_network_value='31.31.31.0/24')
        for sub in itf.sub_interfaces():
            self.assertEqual(sub.address, '31.31.31.254')
            
        # NDI Only
        engine.physical_interface.add_cluster_virtual_interface(
            interface_id=31,
            nodes=[{'address': '31.31.31.1', 'network_value': '31.31.31.0/24', 'nodeid': 1},
                   {'address': '31.31.31.2', 'network_value': '31.31.31.0/24', 'nodeid': 2},
                   {'address': '31.31.31.3', 'network_value': '31.31.31.0/24', 'nodeid': 3}])
        
        itf = engine.interface.get(31)
        itf.change_cluster_ipaddress(
            nodes=[{'address': '32.32.32.1', 'network_value': '32.32.32.0/24', 'nodeid': 1},
                   {'address': '32.32.32.2', 'network_value': '32.32.32.0/24', 'nodeid': 2},
                   {'address': '32.32.32.3', 'network_value': '32.32.32.0/24', 'nodeid': 3}])
        for sub in itf.sub_interfaces():
            self.assertIn(sub.address, ['32.32.32.1','32.32.32.2','32.32.32.3'])
        
        engine.physical_interface.add_ipaddress_and_vlan_to_cluster(
            interface_id=34,
            vlan_id=34,
            cluster_virtual='34.34.34.34',
            cluster_mask='34.34.34.0/24',
            macaddress='02:02:02:04:04:04',
            nodes=[{'address': '34.34.34.1', 'network_value': '34.34.34.0/24', 'nodeid': 1},
                   {'address': '34.34.34.2', 'network_value': '34.34.34.0/24', 'nodeid': 2},
                   {'address': '34.34.34.3', 'network_value': '34.34.34.0/24', 'nodeid': 3}])
        
        itf = engine.interface.get(34)
        
        # Fail if not providing VLAN when interface has VLANs
        with self.assertRaises(UpdateElementFailed):
            itf.change_cluster_ipaddress(cvi='35.35.35.35')
        
        itf.change_cluster_ipaddress(
            cvi='35.35.35.35',
            cvi_network_value='35.35.35.0/24',
            nodes=[{'address': '35.35.35.1', 'network_value': '35.35.35.0/24', 'nodeid': 1},
                   {'address': '35.35.35.2', 'network_value': '35.35.35.0/24', 'nodeid': 2},
                   {'address': '35.35.35.3', 'network_value': '35.35.35.0/24', 'nodeid': 3}],
            vlan_id=34)
        
        for sub in itf.sub_interfaces():
            self.assertIn(sub.address, ['35.35.35.35', '35.35.35.1', '35.35.35.2', '35.35.35.3'])
        
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
                                   nodes=[{'address': '1.1.1.2', 'network_value': '1.1.1.0/24', 'nodeid': 1},
                                          {'address': '1.1.1.3',
                                              'network_value': '1.1.1.0/24', 'nodeid': 2},
                                          {'address': '1.1.1.4', 'network_value': '1.1.1.0/24', 'nodeid': 3}],
                                   domain_server_address=['1.1.1.1'],
                                   zone_ref=zone_helper('Internal'))

        Host('smcpython-fw').delete()
    
    def test_assign_ipaddresses_on_vlans_for_fwcluster(self):
        engine = FirewallCluster.create(name='mycluster',
                                        cluster_virtual='1.1.1.1',
                                        cluster_mask='1.1.1.0/24',
                                        cluster_nic=0,
                                        macaddress='02:02:02:02:02:02',
                                        nodes=[{'address': '1.1.1.2', 'network_value': '1.1.1.0/24', 'nodeid': 1},
                                               {'address': '1.1.1.3', 'network_value': '1.1.1.0/24', 'nodeid': 2}])

        # Create whole interface
        engine.physical_interface.add_ipaddress_and_vlan_to_cluster(
            interface_id=3,
            vlan_id=3,
            cluster_virtual='3.3.3.1',
            cluster_mask='3.3.3.0/24',
            macaddress='02:04:04:04:04:04',
            nodes=[{'address': '3.3.3.2', 'network_value': '3.3.3.0/24', 'nodeid': 1},
                   {'address': '3.3.3.3', 'network_value': '3.3.3.0/24', 'nodeid': 2}])
        

        # CVI AND NDI, no macaddress
        engine.physical_interface.add_ipaddress_and_vlan_to_cluster(
            interface_id=50, vlan_id=50,
            nodes=[{'address': '5.5.5.2', 'network_value': '5.5.5.0/24', 'nodeid': 1},
                   {'address': '5.5.5.3', 'network_value': '5.5.5.0/24', 'nodeid': 2}],
            cluster_virtual='5.5.5.1',
            cluster_mask='5.5.5.0/24',
            macaddress=None,
            cvi_mode='packetdispatch',
            zone_ref=None)

        # Only CVI
        engine.physical_interface.add_ipaddress_and_vlan_to_cluster(
            interface_id=30,
            vlan_id=30,
            cluster_virtual='30.30.30.30',
            cluster_mask='30.30.30.0/24')
        
        engine.physical_interface.set_backup_mgt('30.30')
        itf = engine.physical_interface.get(30)
        for x in itf.sub_interfaces():
            self.assertFalse(x.backup_mgt) 

        # Only NDIs
        engine.physical_interface.add_ipaddress_and_vlan_to_cluster(
            interface_id=31,
            vlan_id=31,
            nodes=[{'address': '4.4.4.2', 'network_value': '4.4.4.0/24', 'nodeid': 1},
                   {'address': '4.4.4.3', 'network_value': '4.4.4.0/24', 'nodeid': 2}])

        engine.physical_interface.add_ipaddress_and_vlan_to_cluster(
            interface_id=31,
            vlan_id=41,
            nodes=[{'address': '44.44.44.2', 'network_value': '44.44.44.0/24', 'nodeid': 1},
                   {'address': '44.44.44.3', 'network_value': '44.44.44.0/24', 'nodeid': 2}])

        engine.physical_interface.set_backup_mgt('31.31')
        itf = engine.physical_interface.get(31)
        for sub in itf.sub_interfaces():
            if sub.vlan_id == '31':
                self.assertTrue(sub.backup_mgt)
        # Unset
        engine.physical_interface.set_backup_mgt(None)
    
        # Just a VLAN on existing interface
        engine.physical_interface.add_ipaddress_and_vlan_to_cluster(
            interface_id=32,
            vlan_id=32)

        for interface in engine.interface.all():
            if interface.name == 'Interface 3':
                for sub_interface in interface.vlan_interfaces():
                    if sub_interface.vlan_id == '3':
                        addresses = sub_interface.address.split(',')
                        for address in ['3.3.3.1', '3.3.3.2', '3.3.3.3']:
                            self.assertIn(address, addresses)
            if interface.name == 'Interface 30':
                for vlan in interface.vlan_interfaces():
                    self.assertEqual(vlan.address, '30.30.30.30')
                    self.assertEqual(vlan.vlan_id, '30')
            if interface.name == 'Interface 31':
                for vlan in interface.vlan_interfaces():
                    addr = vlan.address.split(',')
                    for address in addr:
                        self.assertIn(
                            address, ['4.4.4.2', '4.4.4.3', '44.44.44.2', '44.44.44.3'])
            if interface.name == 'Interface 50':
                self.assertIsNone(interface.macaddress)
                self.assertEqual(interface.cvi_mode, 'none')
                for address in interface.addresses:
                    address, network, vlan = address
                    self.assertIn(address, ['5.5.5.1', '5.5.5.2', '5.5.5.3'])
                    self.assertEqual(network, '5.5.5.0/24')
                    self.assertEqual(vlan, '50.50')

        # Add these to test splitting primary mgt from auth request
        engine.physical_interface.add_ipaddress_and_vlan_to_cluster(
            interface_id=200,
            vlan_id=200, 
            nodes=[{'address': '200.200.200.2', 'network_value': '200.200.200.0/24', 'nodeid': 1},
                   {'address': '200.200.200.3', 'network_value': '200.200.200.0/24', 'nodeid': 2}], 
            cluster_virtual='200.200.200.1', 
            cluster_mask='200.200.200.0/24', 
            macaddress='02:02:02:04:04:04', 
            cvi_mode='packetdispatch')
        
        engine.physical_interface.add_ipaddress_and_vlan_to_cluster(
            interface_id=200,
            vlan_id=201, 
            nodes=[{'address': '201.201.201.2', 'network_value': '201.201.201.0/24', 'nodeid': 1},
                   {'address': '201.201.201.3', 'network_value': '201.201.201.0/24', 'nodeid': 2}],
            cluster_virtual='201.201.201.1', 
            cluster_mask='201.201.201.0/24', 
            macaddress='02:02:02:04:04:04', 
            cvi_mode='packetdispatch')
        
        engine.physical_interface.set_primary_mgt('200.200', '200.201')
        itf = engine.interface.get(200)
        for sub in itf.sub_interfaces():
            if sub.vlan_id == '200':
                if isinstance(sub, NodeInterface):
                    self.assertTrue(sub.primary_mgt)
            elif sub.vlan_id == '201':
                if isinstance(sub, ClusterVirtualInterface):
                    self.assertTrue(sub.auth_request)
         
        # Test moving management to VLAN interface
        engine.physical_interface.set_primary_mgt('3.3')
        itf = engine.interface.get(3)
        self.assertTrue(itf.is_primary_mgt)
        
        # Set back to interface 0 on CVI
        engine.physical_interface.set_primary_mgt(0)
        itf = engine.interface.get(0)
        self.assertTrue(itf.is_primary_mgt)
        
        # Move it to a cluster interface with only NDI. This will fail because auth request
        # needs to be set on CVI
        with self.assertRaises(EngineCommandFailed):
            engine.physical_interface.set_primary_mgt('31.31')
        
        # Now set auth request to CVI
        engine.physical_interface.set_primary_mgt('31.31', auth_request=0)
        itf = engine.interface.get(0)
        for subs in itf.sub_interfaces():
            if isinstance(subs, ClusterVirtualInterface):
                self.assertTrue(subs.auth_request)
    
        itf31 = engine.interface.get(31)
        self.assertTrue(itf31.is_primary_mgt)
        
        # Remove VLAN
        engine.physical_interface.remove_vlan(interface_id=31, vlan_id=41)
        intf = engine.physical_interface.get(30)
        for pvlan in intf.vlan_interfaces():
            self.assertFalse(pvlan.vlan_id == '41')

        # Remove VLAN that doesn't exist
        with self.assertRaises(EngineCommandFailed):
            engine.physical_interface.remove_vlan(interface_id=100, vlan_id=50)

        itf = engine.interface.get(3)
        itf.change_vlan_id(3, 300)
        for interface in itf.vlan_interfaces():
            self.assertEqual(interface.vlan_id, '300')
            
        engine.delete()
    
    #@unittest.skip("tmp")
    def testMasterEngine(self):

        engine = MasterEngine.create('api-master',
                                     mgmt_ip='1.1.1.1',
                                     mgmt_network='1.1.1.0/24',
                                     master_type='firewall',
                                     domain_server_address=['8.8.8.8', '7.7.7.7'])
        self.assertIsInstance(engine, Engine)
        # Test repr
        self.assertTrue(repr(engine) == '%s(name=%s)' %
                        (lookup_class(engine.type).__name__, engine.name))

        # Load directly
        engine = MasterEngine('api-master')
        engine.physical_interface.add(1)
        engine.physical_interface.add(2)
        engine.physical_interface.add(3)
        engine.physical_interface.add_vlan_to_node_interface(interface_id=4, vlan_id=4)
    
        intf = engine.physical_interface.get(1)
        self.assertFalse(intf.addresses)
        
        # Change VLAN on master engine, only VLAN
        itf = engine.interface.get(4)
        itf.change_vlan_id(4, 40)
        for x in itf.vlan_interfaces():
            self.assertEqual(x.vlan_id, '40')
    
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
        # Single master engine, no cluster
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
                self.assertFalse(interface.addresses)

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
        # Test repr
        self.assertTrue(repr(virtualengine) == '%s(name=%s)' % (
            lookup_class(virtualengine.type).__name__, virtualengine.name))

        # Load directly
        virtualengine = Layer3VirtualEngine('myvirtual')

        for interface in virtualengine.interface.all():
            address, network, _ = interface.addresses[0]
            self.assertIn(address, '1.1.1.1')
            self.assertIn(network, '1.1.1.0/24')

        # Test engine add-ons. Some are not supported to be enabled directly on the virtual instance,
        # and instead should be enabled on the Master Engine.
        self.assertFalse(virtualengine.is_sidewinder_proxy_enabled)
        virtualengine.enable_sidewinder_proxy()
        self.assertTrue(virtualengine.is_sidewinder_proxy_enabled)
        virtualengine.disable_sidewinder_proxy()
        self.assertFalse(virtualengine.is_sidewinder_proxy_enabled)

        if is_min_required_smc_version('6.2.0'):
            # DNS Relay
            self.assertFalse(virtualengine.is_dns_relay_enabled)
            virtualengine.enable_dns_relay(interface_id=0)
            self.assertTrue(virtualengine.is_dns_relay_enabled)
            virtualengine.disable_dns_relay()
            self.assertFalse(virtualengine.is_dns_relay_enabled)

        # AV - should be on MasterEngine
        with self.assertRaises(UnsupportedEngineFeature):
            virtualengine.enable_antivirus()

        # GTI, should be on Master Engine
        with self.assertRaises(UnsupportedEngineFeature):
            virtualengine.enable_gti_file_reputation()

        # Sandbox should be on Master Engine
        with self.assertRaises(UnsupportedEngineFeature):
            virtualengine.is_sandbox_enabled

        # URL Filtering should be on Mater Engine
        with self.assertRaises(UnsupportedEngineFeature):
            virtualengine.enable_url_filtering()

        # OSPF supported on this engine
        self.assertFalse(virtualengine.is_ospf_enabled)
        virtualengine.enable_ospf()
        self.assertTrue(virtualengine.is_ospf_enabled)
        virtualengine.disable_ospf()
        self.assertFalse(virtualengine.is_ospf_enabled)

        # BGP
        Network.create(name='bgpnet', ipv4_network='1.1.1.0/24')
        self.assertFalse(engine.is_bgp_enabled)
        AutonomousSystem.create(name='myas', as_number=100)
        virtualengine.enable_bgp(autonomous_system=AutonomousSystem('myas'),
                                 announced_networks=[(Network('bgpnet'))])
        self.assertTrue(virtualengine.is_bgp_enabled)
        virtualengine.disable_bgp()
        self.assertFalse(virtualengine.is_bgp_enabled)

        # Master engine does not run BGP, virtual instances do
        with self.assertRaises(UpdateElementFailed):
            engine.enable_bgp(autonomous_system=AutonomousSystem('myas'),
                              announced_networks=[Network('bgpnet')],
                              autocommit=True)

        virtualengine.delete()
        engine.delete()
        AutonomousSystem('myas').delete()
        Network('bgpnet').delete()

    #@unittest.skip("tmp")
    def testVirtualLayer3Engine(self):

        masterengine = MasterEngine.create('api-master',
                                           mgmt_ip='1.1.1.1',
                                           mgmt_network='1.1.1.0/24',
                                           master_type='firewall',
                                           domain_server_address=['8.8.4.4', '7.7.7.7'])

        virtual_resource = masterengine.virtual_resource.create(
            name='ve-10', vfw_id=1)
        self.assertTrue(virtual_resource.startswith('http'))

        masterengine.physical_interface.add_vlan_to_node_interface(interface_id=1,
                                                                   vlan_id=100,
                                                                   virtual_mapping=0,
                                                                   virtual_resource_name='ve-10')

        # Master engine must exist and be online or interface will show with
        # red X through it
        engine = Layer3VirtualEngine.create('layer3-ve',
                                            master_engine='api-master',
                                            virtual_resource='ve-10',
                                            interfaces=[{'interface_id': 0,
                                                         'address': '1.1.1.1',
                                                          'network_value': '1.1.1.0/24'}])
        self.assertIsInstance(engine, Engine)
        
        # Virtual engines dont have primary mgt, but do have auth request
        # and outgoing
        engine.virtual_physical_interface.set_primary_mgt(0)
        
        itf = engine.virtual_physical_interface.get(0)
        for sub in itf.sub_interfaces():
            self.assertEqual(sub.address, '1.1.1.1')
            self.assertEqual(sub.network_value, '1.1.1.0/24')
            self.assertTrue(sub.auth_request)
            self.assertTrue(sub.outgoing)
            self.assertFalse(sub.primary_mgt)

        '''
        domain = AdminDomain.create('virtualdomain')
        
        for virtual in masterengine.virtual_resource:
            if virtual.name == 've-10':
                virtual.connection_limit = 1000
                virtual.show_master_nic = True
                virtual.set_admin_domain(domain)
                virtual.update()
        
        for virtual in masterengine.virtual_resource:
            if virtual.name == 've-10':
                self.assertEqual(virtual.connection_limit, 1000)
                self.assertEqual(virtual.show_master_nic, True)
                self.assertEqual(virtual.allocated_domain_ref, domain.href)
        '''    
        engine.delete()
        masterengine.delete()

    #@unittest.skip("tmp")
    def test_masterEngine_cluster(self):
        # Test creating MasterEngineCluster
        engine = MasterEngineCluster.create(
            name='engine-cluster',
            master_type='firewall',
            macaddress='22:22:22:22:22:22',
            nodes=[{'address': '5.5.5.2', 'network_value': '5.5.5.0/24', 'nodeid': 1},
                   {'address': '5.5.5.3', 'network_value': '5.5.5.0/24', 'nodeid': 2}])
        
        self.assertIsInstance(engine, Engine)
        # Test repr
        self.assertTrue(repr(engine) == '%s(name=%s)' %
                        (lookup_class(engine.type).__name__, engine.name))

        # Load directly
        engine = MasterEngineCluster('engine-cluster')
        # Create another interface
        engine.physical_interface.add_cluster_interface_on_master_engine(
            interface_id=1,
            macaddress='22:22:22:22:22:33',
            nodes=[{'address': '6.6.6.2', 'network_value': '6.6.6.0/24', 'nodeid': 1},
                   {'address': '6.6.6.3', 'network_value': '6.6.6.0/24', 'nodeid': 2}])

        itf = engine.interface.get(0)
        self.assertEqual(itf.macaddress, '22:22:22:22:22:22')
        for addr in itf.addresses:
            self.assertIn(addr[0], ['5.5.5.2', '5.5.5.3'])

        engine.physical_interface.set_primary_mgt(1)
        itf = engine.physical_interface.get(1)
        self.assertTrue(itf.is_primary_mgt)
        # Master Engine only has Node Interfaces. Auth Request is not valid
        for sub in itf.sub_interfaces():
            self.assertFalse(sub.auth_request)
        
        # Simulate failed creation of master engine (preexisting with same
        # name)
        with self.assertRaises(CreateEngineFailed):
            MasterEngineCluster.create(name='engine-cluster',
                                       master_type='firewall',
                                       macaddress='22:22:22:22:22:22',
                                       nodes=[{'address': '5.5.5.2',
                                               'network_value': '5.5.5.0/24',
                                               'nodeid': 1},
                                              {'address': '5.5.5.3',
                                               'network_value': '5.5.5.0/24',
                                               'nodeid': 2}])
        engine.delete()

    #@unittest.skip("tmp")
    def test_full_masterenginecluster_with_virtualengines(self):
        engine = MasterEngineCluster.create(
            name='engine-cluster',
            master_type='firewall',
            macaddress='22:22:22:22:22:22',
            nodes=[{'address': '5.5.5.2',
                    'network_value': '5.5.5.0/24',
                    'nodeid': 1},
                   {'address': '5.5.5.3',
                    'network_value': '5.5.5.0/24',
                    'nodeid': 2}])
        self.assertIsInstance(engine, Engine)

        result = engine.virtual_resource.create(name='ve-1', vfw_id=1,
                                                connection_limit=10)
        self.assertTrue(result.startswith('http'))
        for virtuals in engine.virtual_resource:
            if virtuals.name == 've-1':
                self.assertEqual(virtuals.vfw_id, 1)
                self.assertFalse(virtuals.show_master_nic)
                self.assertEqual(virtuals.connection_limit, 10)
                self.assertEqual(
                    virtuals.allocated_domain_ref.name, 'Shared Domain')

        engine.physical_interface.add_vlan_to_node_interface(
            interface_id=1,
            vlan_id=100,
            virtual_mapping=0,
            virtual_resource_name='ve-1')

        for interface in engine.interface.all():
            if interface.name == 'Interface 0':
                for addresses in interface.addresses:
                    address, network, nicid = addresses
                    self.assertIn(address, ['5.5.5.2', '5.5.5.3'])
                    self.assertIn(network, ['5.5.5.0/24'])
                    self.assertIn(nicid, ['0'])
                self.assertEqual(interface.macaddress, '22:22:22:22:22:22')
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
        Engine('engine-cluster').delete()

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
                    self.assertIn(intf.network_value, [
                                  '2.2.2.0/24', '13.13.13.0/24'])
            elif interface.name == 'Interface 20':
                self.assertTrue(interface.zone_ref.startswith('http'))
                for intf in interface.sub_interfaces():
                    self.assertEqual(intf.dynamic_index, 1)

        engine.delete()

    def test_tunnel_cvi_ndi(self):
        engine = FirewallCluster.create(name='mycluster',
                                        cluster_virtual='1.1.1.1',
                                        cluster_mask='1.1.1.0/24',
                                        cluster_nic=0,
                                        macaddress='02:02:02:02:02:02',
                                        nodes=[{'address': '1.1.1.2', 'network_value': '1.1.1.0/24', 'nodeid': 1},
                                               {'address': '1.1.1.3',
                                                   'network_value': '1.1.1.0/24', 'nodeid': 2},
                                               {'address': '1.1.1.4', 'network_value': '1.1.1.0/24', 'nodeid': 3}],
                                        domain_server_address=['1.1.1.1'],
                                        zone_ref=zone_helper('Internal'))
        self.assertIsInstance(engine, Engine)
        # Add just a CVI
        engine.tunnel_interface.add_cluster_virtual_interface(tunnel_id=1001,
                                                              cluster_virtual='23.23.23.23',
                                                              cluster_mask='23.23.23.0/24',
                                                              zone_ref=zone_helper('tmpzone'))

        # Add CVI and NDI (no mac required for Tunnel Interface)
        engine.tunnel_interface.add_cluster_virtual_interface(
            tunnel_id=1055,
            cluster_virtual='77.77.77.77',
            cluster_mask='77.77.77.0/24',
            nodes=[{'address': '77.77.77.78', 'network_value': '77.77.77.0/24', 'nodeid': 1},
                   {'address': '77.77.77.79',
                               'network_value': '77.77.77.0/24', 'nodeid': 2},
                   {'address': '77.77.77.80', 'network_value': '77.77.77.0/24', 'nodeid': 3}])

        for interface in engine.interface.all():
            if interface.name == 'Interface 0':
                self.assertEqual(interface.macaddress, '02:02:02:02:02:02')
                for address in interface.addresses:
                    address, _, _ = address
                    self.assertIn(
                        address, ['1.1.1.1', '1.1.1.2', '1.1.1.3', '1.1.1.4'])
            elif interface.name == 'Tunnel Interface 1001':
                address, _, _ = interface.addresses[0]
                self.assertEqual(address, '23.23.23.23')
                self.assertTrue(interface.zone_ref.startswith('http'))
            elif interface.name == 'Tunnel Interface 1055':
                for intf in interface.addresses:
                    address, _, _ = intf
                    self.assertIn(
                        address, ['77.77.77.77', '77.77.77.78', '77.77.77.79', '77.77.77.80'])
        
        itf = engine.interface.get(0)
        itf.change_interface_id(100)
        for sub in itf.sub_interfaces():
            self.assertIn(sub.address, ['1.1.1.1','1.1.1.2','1.1.1.3','1.1.1.4'])
            
        itf = engine.interface.get(1001)
        itf.change_interface_id(1010)
        self.assertEqual(itf.interface_id, '1010')
        
        engine.delete()

    def test_contact_addr_on_physical_and_tunnel(self):
        engine = Layer3Firewall.create('myfw',
                                       '1.1.1.1',
                                       '1.1.1.0/24')
        self.assertIsInstance(engine, Engine)

        engine.tunnel_interface.add_single_node_interface(tunnel_id=1000,
                                                          address='10.10.10.10',
                                                          network_value='10.10.10.0/24')

        # Test all() alternative to getting contactinterfaces
        for interfaces in engine.contact_addresses.all():
            self.assertIsInstance(interfaces, InterfaceContactAddress)

        # Add contact address from physical interface
        for intf in engine.physical_interface.all():
            if intf.name == 'Interface 0':
                self.assertIsInstance(
                    intf.contact_addresses[0], InterfaceContactAddress)  # Contact interface
                self.assertEqual(intf.contact_addresses[0].address, '1.1.1.1')
            
                self.assertFalse(
                    intf.contact_addresses[0].contact_addresses)  # Empty
                # Add from engine level
                contact_addr = engine.contact_addresses(0)
                self.assertIsInstance(contact_addr, list)
                contact_addr[0].add_contact_address('12.12.12.12')
                
                # TEST REPR
                for testrepr in contact_addr:
                    self.assertTrue((repr(testrepr) == '%s(name=Interface 0,address=%s)' % 
                            (type(testrepr).__name__, testrepr.address)))

                # Add a second contact address
                contact_addr[0].add_contact_address(
                    contact_address='13.13.13.13', location='MyLocation')

                for contact_interface in intf.contact_addresses:
                    for address in contact_interface.contact_addresses:
                        self.assertIn(address.address, [
                                      '12.12.12.12', '13.13.13.13'])
                        self.assertIn(address.location, [
                                      'MyLocation', 'Default'])
                        self.assertFalse(address.dynamic)

                # Add contact address with default, overwriting the previous
                c = intf.contact_addresses
                self.assertIsNone(c[0].add_contact_address('22.22.22.22'))
                for interface in intf.contact_addresses:
                    for contact_addr in interface.contact_addresses:
                        self.assertIn(contact_addr.address, [
                                      '22.22.22.22', '13.13.13.13'])

                # Remove the '13.13.13.13' contact address
                self.assertIsNone(c[0].remove_contact_address('13.13.13.13'))
                for interface in intf.contact_addresses:
                    for contact_addr in interface.contact_addresses:
                        self.assertIn(contact_addr.address, ['22.22.22.22'])

        # Contact Addresses applied to Tunnel Interfaces
        interface = engine.contact_addresses(1000)
        for contact_interface in interface:
            self.assertIsInstance(contact_interface, InterfaceContactAddress)
            self.assertFalse(contact_interface.contact_addresses)
            contact_interface.add_contact_address('66.66.66.66')
            for addr in contact_interface.contact_addresses:
                self.assertEqual(addr.address, '66.66.66.66')

        engine.delete()
    
    def test_static_netlink(self):
        engine = Layer3Firewall.create(name='netlinkfw', 
                                       mgmt_ip='1.1.1.1', 
                                       mgmt_network='1.1.1.0/24')
        
        engine.physical_interface.add_single_node_interface(
            interface_id=0,
            address='2.2.2.2',
            network_value='2.2.2.0/24')
        
        Network.create(name='mynetwork', ipv4_network='2.2.2.0/24')
        n = StaticNetlink.create(name='netlink', 
                                 gateway=engine, 
                                 network=[Network('mynetwork')], 
                                 input_speed=3000, 
                                 output_speed=3000, 
                                 domain_server_address=['23.23.23.23','33.33.33.33'], 
                                 provider_name='someprovider', 
                                 probe_address=['1.1.1.254'], 
                                 standby_mode_period=10, 
                                 standby_mode_timeout=10, 
                                 active_mode_period=10, 
                                 active_mode_timeout=10, 
                                 comment='foobar')

        #Check netlink settings
        netlink = StaticNetlink('netlink')
        self.assertEqual(netlink.gateway.name, engine.name)
        for network in netlink.networks:
            self.assertEqual(network.name, 'mynetwork')
        self.assertEqual(netlink.input_speed, 3000)
        self.assertEqual(netlink.output_speed, 3000)
        self.assertEqual(netlink.standby_mode_period, 10)
        self.assertEqual(netlink.standby_mode_timeout, 10)
        self.assertEqual(netlink.active_mode_period, 10)
        self.assertEqual(netlink.active_mode_timeout, 10)
        for dns in netlink.domain_server_address:
            self.assertIn(dns, ['23.23.23.23','33.33.33.33'])
        self.assertIn('1.1.1.254', netlink.probe_address)
        
        '''
        netlink.modify_attribute(input_speed=4000,
                                 output_speed=4000,
                                 standby_mode_period=20,
                                 standby_mode_timeout=20,
                                 active_mode_period=20,
                                 active_mode_timeout=20)
        
        print("Modified")
        self.assertEqual(netlink.input_speed, 4000)
        self.assertEqual(netlink.output_speed, 4000)
        self.assertEqual(netlink.standby_mode_period, 20)
        self.assertEqual(netlink.standby_mode_timeout, 20)
        self.assertEqual(netlink.active_mode_period, 20)
        self.assertEqual(netlink.active_mode_timeout, 20)
        '''   
        rnode = engine.routing.get(0)
        rnode.add_traffic_handler(n)
        
        # Netlinks are initially on BOTH interfaces as no 'network=' was specified
        for routes in rnode:
            # routes = Network level node
            for networks in routes:
                self.assertEqual(networks.name, 'netlink') #Nested network Gateways
        
        # Remove from ALL network interfaces
        rnode.remove_route_element(StaticNetlink('netlink'))
        
        # Re-add but only to the 2.2.2.0/24 network on interface 0 and use
        # a netlink GW
        Router.create(name='myrtr', address='2.2.2.254')
        rnode.add_traffic_handler(n, netlink_gw=Router('myrtr'), network='2.2.2.0/24')
        for routes in rnode:
            if routes.ip == '2.2.2.0/24':
                for networks in routes:
                    self.assertEqual(networks.name, 'netlink') #Nested network Gateways
                    for level_any in networks:
                        self.assertEqual(level_any.name, 'myrtr')
            else:
                for networks in routes:
                    self.assertFalse(networks)
        
        # If this fails, the static netlink will prevent the netlink from being deleted
        # due to dependency on the engine.
        rnode.remove_route_element(StaticNetlink('netlink'), network='2.2.2.0/24')
        
        netlink.delete()    
        engine.delete()
        Network('mynetwork').delete()
    
    def test_create_dhcp_firewall(self):
        engine = Layer3Firewall.create_dynamic(
            name='azure', 
            interface_id=0,
            dynamic_index=1,
            default_nat=True,
            location_ref=location_helper('Internet'))

        network = Network.get_or_create(
            filter_key={'ipv4_network': '192.168.0.0/16'},
            name='internal_network',
            ipv4_network='192.168.0.0/16')
    
        route = engine.routing.get(0)
        route.add_dynamic_gateway([network])
        
        interface = engine.routing.get(0)
        for network in interface:
            for gateway in network:
                for route in gateway:
                    self.assertIn(route.ip, ['0.0.0.0/0', '192.168.0.0/16'])
    
        with self.assertRaises(CreateEngineFailed):
            Layer3Firewall.create_dynamic(
                name='azure', 
                interface_id=0)
        
if __name__ == "__main__":
    unittest.main()

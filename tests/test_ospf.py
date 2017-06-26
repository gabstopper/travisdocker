'''
Created on Oct 29, 2016

@author: davidlepage
'''
import unittest
from smc.tests.constants import url, api_key, verify
from smc import session
from smc.elements.network import Host, Network
from smc.routing.ospf import OSPFKeyChain, OSPFInterfaceSetting, OSPFArea,\
    OSPFDomainSetting, OSPFProfile
from smc.core.engines import Layer3Firewall
from smc.core.engine import Engine
from smc.base.collection import Search
from smc.routing.bgp import BGPProfile, AutonomousSystem, ExternalBGPPeer,\
    BGPConnectionProfile, BGPPeering


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
        self.assertTrue(key_chain.href.startswith('http'))

        # Find and delete through collections
        key_chain = list(
            Search('ospfv2_key_chain').objects.filter('smcpython-keychain'))
        key_chain[0].delete()

    def test_ospf_key_chain_and_ospf_interface_setting(self):
        key_chain = OSPFKeyChain.create(name='smcpython-keychain',
                                        key_chain_entry=[{'key': 'fookey',
                                                          'key_id': 10,
                                                          'send_key': True}])
        self.assertTrue(key_chain.href.startswith('http'))
        ospf_interface = OSPFInterfaceSetting.create(name='smcpython-ospf',
                                                     authentication_type='message_digest',
                                                     key_chain_ref=key_chain)
        self.assertTrue(ospf_interface.href.startswith('http'))
        o = OSPFInterfaceSetting('smcpython-ospf')
        self.assertTrue(o.href.startswith('http'))

        # Delete interface setting first
        ospf_intf = list(
            Search('ospfv2_interface_settings').objects.filter('smcpython-ospf'))
        ospf_intf[0].delete()

        key_chain = list(
            Search('ospfv2_key_chain').objects.filter('smcpython-keychain'))
        key_chain[0].delete()

    def test_ospf_area(self):

        for profile in list(Search('ospfv2_interface_settings').objects.all()):
            if profile.name.startswith('Default OSPF'):  # Use the system default
                interface_profile = profile.href

        area = OSPFArea.create(name='area-smcpython',
                               interface_settings_ref=interface_profile,
                               area_id=0)
        self.assertTrue(area.href.startswith('http'))

        area = OSPFArea('area-smcpython')
        self.assertEqual(area.interface_settings_ref.name,
                         'Default OSPFv2 Interface Settings')
        area.delete()

        # Test without interface setting, it will use default
        intf = OSPFInterfaceSetting('Default OSPFv2 Interface Settings').href
        OSPFArea.create(name='area0', area_id=0)
        area = OSPFArea('area0')
        self.assertEqual(area.data.get('interface_settings_ref'), intf)
        area.delete()

    def test_ospf_domain_and_ospf_profile(self):

        domain = OSPFDomainSetting.create(name='smcpython-domain',
                                          abr_type='cisco')
        self.assertTrue(domain.href.startswith('http'))

        ospf_domain = OSPFDomainSetting('smcpython-domain')  # obtain resource

        OSPFProfile.create(name='smcpython-profile',
                           domain_settings_ref=ospf_domain,
                           inter_distance=100,
                           intra_distance=150,
                           external_distance=200)

        ospf_profile = OSPFProfile('smcpython-profile')
        self.assertEqual(ospf_profile.inter_distance, 100)
        self.assertEqual(ospf_profile.intra_distance, 150)
        self.assertEqual(ospf_profile.external_distance, 200)

        # Create profile with no ospf domain setting, verify it received the
        # default
        OSPFProfile.create(name='fooprofile')
        testprofile = OSPFProfile('fooprofile')
        ospfdomainsetting = testprofile.domain_settings_ref
        self.assertEqual(ospfdomainsetting.name,
                         'Default OSPFv2 Domain Settings')

        # Delete profile first
        OSPFProfile('smcpython-profile').delete()
        OSPFDomainSetting('smcpython-domain').delete()

    def test_create_layer3_firewall_and_add_ospf(self):

        for profile in list(Search('ospfv2_interface_settings').objects.all()):
            if profile.name.startswith('Default OSPF'):
                interface_profile = profile.href

        area = OSPFArea.create(name='smcpython-area',
                               interface_settings_ref=interface_profile,
                               area_id=0)
        self.assertTrue(area.href.startswith('http'))

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
        # Get routing resources
        for interface in engine.routing.all():
            # if interface.name == 'Interface 0':
            if interface.nicid == '0':
                # Apply OSPF 'area0' to interface 0
                interface.add_ospf_area(area)
                for networks in interface.all():  # Traverse networks
                    self.assertIn(networks.name, [
                                  'network-172.18.1.0/24', 'network-2001:db8:85a3::/64'])
                    self.assertTrue(networks.level == 'network')

        # Add only to specified network
        for interface in engine.routing.all():
            if interface.name == 'Interface 0':
                interface.add_ospf_area(area, network='172.18.1.0/24')

        engine.delete()
        area.delete()

    def test_ospf_unicast(self):

        for profile in list(Search('ospfv2_interface_settings').objects.all()):
            if profile.name.startswith('Default OSPF'):
                interface_profile = profile.href

        area = OSPFArea.create(name='smcpython-area',
                               interface_settings_ref=interface_profile,
                               area_id=0)
        self.assertTrue(area.href.startswith('http'))

        area = OSPFArea('smcpython-area')

        engine = Layer3Firewall.create(name='smcpython-ospf',
                                       mgmt_ip='172.18.1.30',
                                       mgmt_network='172.18.1.0/24',
                                       domain_server_address=['8.8.8.8'],
                                       enable_ospf=True)

        self.assertIsInstance(engine, Engine)
        host = Host.create(name='smcpython-ospf-user', address='23.23.23.23')

        # Get routing resources
        for interface in engine.routing.all():
            if interface.name == 'Interface 0':
                result = interface.add_ospf_area(area, communication_mode='unicast',
                                                 unicast_ref=host)
                self.assertIsNone(result)

        engine.delete()
        area.delete()

        Host('smcpython-ospf-user').delete()

    def test_bgp_profile(self):
        """
        Test BGP Profiles
        """
        Network.create(name='bgpnet', ipv4_network='1.1.1.0/24')
        profile = BGPProfile.create(name='myprofile',
                                    port=300,
                                    external_distance=100,
                                    internal_distance=150,
                                    local_distance=200,
                                    subnet_distance=[(Network('bgpnet'), 100)])

        self.assertTrue(profile.href.startswith('http'))
        myprofile = BGPProfile('myprofile')

        self.assertEqual(myprofile.port, 300)
        self.assertEqual(myprofile.internal_distance, 150)
        self.assertEqual(myprofile.external_distance, 100)
        self.assertEqual(myprofile.local_distance, 200)
        for subnet in myprofile.subnet_distance:
            self.assertEqual(subnet[0].name, 'bgpnet')
            self.assertEqual(subnet[1], 100)
        myprofile.delete()
        Network('bgpnet').delete()

    def test_autonomous_system(self):
        a = AutonomousSystem.create(name='auton', as_number=200)
        self.assertTrue(a.href.startswith('http'))

        a = AutonomousSystem('auton')
        self.assertEqual(a.as_number, 200)
        AutonomousSystem('auton').delete()

    def test_external_bgp_peer(self):
        AutonomousSystem.create(name='myas', as_number=100)
        ExternalBGPPeer.create(name='mypeer',
                               neighbor_as_ref=AutonomousSystem('myas'),
                               neighbor_ip='1.1.1.1')
        peer = ExternalBGPPeer('mypeer')
        self.assertEqual(peer.neighbor_ip, '1.1.1.1')
        self.assertEqual(peer.neighbor_port, 179)
        self.assertEqual(peer.neighbor_as.name, 'myas')

    def test_bgp_connection_profile(self):
        BGPConnectionProfile.create(name='fooprofile',
                                    md5_password='12345',
                                    connect_retry=200,
                                    session_hold_timer=100,
                                    session_keep_alive=150)
        b = BGPConnectionProfile('fooprofile')
        self.assertEqual(b.connect_retry, 200)
        self.assertEqual(b.session_hold_timer, 100)
        self.assertEqual(b.session_keep_alive, 150)
        b.delete()

    def test_bgp_peering(self):
        BGPConnectionProfile.create(name='fooprofile')
        BGPPeering.create(name='mypeering',
                          connection_profile_ref=BGPConnectionProfile(
                              'fooprofile'),
                          md5_password='12345')
        profile = BGPPeering('mypeering')
        self.assertEqual(profile.connection_profile.name, 'fooprofile')

        BGPPeering.create(name='defaultpeering')
        b = BGPPeering('defaultpeering')
        self.assertEqual(b.connection_profile.name,
                         'Default BGP Connection Profile')

        profile.delete()

    def test_create_engine_add_bgp_peering(self):

        engine = Layer3Firewall.create(name='myfw',
                                       mgmt_ip='1.1.1.1',
                                       mgmt_network='1.1.1.0/24')

        engine.physical_interface.add_single_node_interface(interface_id=0,
                                                            address='5.5.5.5',
                                                            network_value='5.5.5.0/24')

        Network.create(name='bgpnet', ipv4_network='2.2.2.0/24')
        AutonomousSystem.create(name='aws_as', as_number=20000)
        engine.enable_bgp(autonomous_system=AutonomousSystem('aws_as'),
                          announced_networks=[Network('bgpnet')])
        BGPPeering.create(name='mypeer')
        ExternalBGPPeer.create(name='neighbor',
                               neighbor_as_ref=AutonomousSystem('aws_as'),
                               neighbor_ip='3.3.3.3')

        # Only add to a single network
        for route in engine.routing.all():
            if route.nicid == '0':
                route.add_bgp_peering(
                    BGPPeering('mypeer'),
                    ExternalBGPPeer('neighbor'),
                    network='5.5.5.0/24')

        # Traverse the nested routing tree..
        for route in engine.routing.all():
            if route.nicid == '0':
                for bgp_peering in route.all():
                    if bgp_peering.ip == '5.5.5.0/24':
                        for peering in bgp_peering.all():  # BGPPeering
                            self.assertEqual(peering.name, 'mypeer')
                            for external_peer in peering.all():  # ExternalBGPPeer
                                self.assertEqual(
                                    external_peer.name, 'neighbor')
        engine.delete()

        # Add BGP to all interfaces
        engine = Layer3Firewall.create(name='myfw',
                                       mgmt_ip='1.1.1.1',
                                       mgmt_network='1.1.1.0/24')

        engine.physical_interface.add_single_node_interface(interface_id=0,
                                                            address='5.5.5.5',
                                                            network_value='5.5.5.0/24')
        # Only add to a single network
        interface = engine.routing.get(0)
        # for route in engine.routing.all():
        #    if route.nicid == '0':
        interface.add_bgp_peering(
            BGPPeering('mypeer'),
            ExternalBGPPeer('neighbor'))

        for route in engine.routing.all():
            if route.nicid == '0':
                for bgp_peering in route.all():
                    for peering in bgp_peering.all():
                        self.assertEqual(peering.name, 'mypeer')  # BGPPeering
                        for external_peer in peering.all():
                            # ExternalBGPPeer
                            self.assertEqual(external_peer.name, 'neighbor')
        engine.delete()


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()

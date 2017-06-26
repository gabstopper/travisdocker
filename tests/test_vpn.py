'''
Created on Oct 2, 2016

@author: davidlepage
'''
import unittest
from smc.tests.constants import url, api_key, verify
from smc import session
from smc.vpn.policy import VPNPolicy, GatewayNode, GatewayTreeNode
from smc.vpn.elements import ExternalGateway, GatewaySettings, \
    GatewayProfile, VPNProfile
from smc.elements.network import Network
from smc.api.exceptions import ElementNotFound, CreatePolicyFailed,\
    CreateElementFailed, PolicyCommandFailed
from smc.core.engines import Layer3Firewall
from smc.core.engine import Engine
from smc.base.collection import Search


class Test(unittest.TestCase):

    def setUp(self):
        session.login(url=url, api_key=api_key, verify=verify)

    def tearDown(self):
        session.logout()

    def test_add_vpn_policy(self):
        result = VPNPolicy.create(name='smcpythonVPN', nat=True)
        self.assertIsInstance(result, VPNPolicy)
        self.assertTrue(result.nat)
        result.enable_disable_nat()  # Disable NAT
        self.assertFalse(result.nat)
        result.enable_disable_nat()  # Enable it again
        self.assertTrue(result.nat)

        with self.assertRaises(CreatePolicyFailed):
            VPNPolicy.create(name='smcpythonVPN')

        # Check VPN Profile
        self.assertIsNotNone(result.vpn_profile)

        for x in list(Search('vpn').objects.filter('smcpythonVPN')):
            self.assertTrue(x.href.startswith('http'))
            x.delete()

    def test_create_vpn_policy_with_profile(self):
        profile = VPNProfile.objects.first()
        print(profile)
        v = VPNPolicy.create(name='vpnwithprofile', vpn_profile=profile)
        self.assertEqual(v.vpn_profile.name, profile.name)
        
    def test_add_external_gateway_endpoint_and_vpnsite(self):
        for gw in list(Search('external_gateway').objects.filter('smcpython-externalgw')):
            gw.delete()

        result = ExternalGateway.create(name='smcpython-externalgw')
        self.assertIsInstance(result, ExternalGateway)
        e = ExternalGateway('smcpython-externalgw')
        self.assertTrue(e.trust_all_cas)
        self.assertIsInstance(e.gateway_profile, GatewayProfile)

        # For vpn site
        network = Network.create('py4.4.4.0', '4.4.4.0/24')

        e = ExternalGateway('smcpython-externalgw')
        # for x in list(Search('external_gateway').objects.filter('smcpython-externalgw')):
        #    self.assertIsNotNone(x.href) #have meta
        res = e.external_endpoint.create(
            'myendpoint', '1.1.1.1')  # create endpoint
        self.assertTrue(res.startswith('http'))

        # Invalid endpoint
        with self.assertRaises(CreateElementFailed):
            e.external_endpoint.create('myendpoint', '1.1.1.1a')

        # Fail test_external gateway
        with self.assertRaises(CreateElementFailed):
            ExternalGateway.create('smcpython-externalgw')

        site = e.vpn_site.create('pythonsite', [network])  # Create vpn site
        self.assertTrue(site.startswith('http'))

        with self.assertRaises(CreateElementFailed):
            e.vpn_site.create('poosite', ['http://1.1.1.1'])

        # Add an additional network to an existing VPN Site
        network = Network.create('pythonnetwork', '23.23.23.0/24')

        gw = ExternalGateway('smcpython-externalgw')
        for sites in gw.vpn_site.all():
            self.assertEqual(sites.name, 'pythonsite')
            self.assertTrue(sites.site_element)
            sites.add_site_element([network])    # Add a network to site list
            for network in sites.site_element:
                self.assertIn(network.name, ['pythonnetwork', 'py4.4.4.0'])

            internal_gateway = sites.gateway
            self.assertEqual(internal_gateway.name, 'smcpython-externalgw')

        e = ExternalGateway('smcpython-externalgw')
        for endpoint in e.external_endpoint:
            self.assertFalse(endpoint.force_nat_t)  # Disabled
            endpoint.enable_disable_force_nat_t()  # Enable
            self.assertTrue(endpoint.force_nat_t)
            endpoint.enable_disable_force_nat_t()  # Disable again
            self.assertFalse(endpoint.force_nat_t)  # Disabled

            self.assertTrue(endpoint.enabled)  # Enabled
            endpoint.enable_disable()  # Disable
            self.assertFalse(endpoint.enabled)
            endpoint.enable_disable()  # Enable again
            self.assertTrue(endpoint.enabled)

        gw.delete()

        for network in list(Search('network').objects.all()):
            if network.name == 'py4.4.4.0' or network.name == 'pythonnetwork':
                network.delete()

    def test_load_non_existant_external_gw(self):
        with self.assertRaises(ElementNotFound):
            ExternalGateway('wrgrgshfhfdh').data

    def test_add_VPN_external_and_satellite_gw(self):
        firewall_central = Layer3Firewall.create(
                            'centralfw', mgmt_ip='1.1.1.1',
                            mgmt_network='1.1.1.0/24')
        
        self.assertIsInstance(firewall_central, Engine)
        firewall_satellite = Layer3Firewall.create(
                            'satellitefw', mgmt_ip='2.2.2.2',
                            mgmt_network='2.2.2.0/24')
        
        self.assertIsInstance(firewall_satellite, Engine)

        policy = VPNPolicy.create(name='tmptestvpn')
        self.assertIsInstance(policy, VPNPolicy)

        self.assertTrue(VPNPolicy.add_internal_gateway_to_vpn(
            firewall_central.internal_gateway.href,
            vpn_policy='tmptestvpn',
            vpn_role='central'))
        
        self.assertTrue(VPNPolicy.add_internal_gateway_to_vpn(
            firewall_satellite.internal_gateway.href,
            vpn_policy='tmptestvpn',
            vpn_role='satellite'))
        
        # Invalid vpn policy
        self.assertFalse(VPNPolicy.add_internal_gateway_to_vpn(
            firewall_central.internal_gateway.href,
            vpn_policy='foobar'))

        with self.assertRaises(PolicyCommandFailed):
            policy.close()

        policy.open()

        for gw in policy.central_gateway_node.all():
            self.assertFalse(list(gw.disabled_sites))
            for site in list(gw.enabled_sites):
                self.assertTrue('centralfw' in site.name)
                site.enable_disable()
            for site in list(gw.disabled_sites):
                self.assertTrue('centralfw' in site.name)
                site.enable_disable()
            for site in list(gw.enabled_sites):
                self.assertTrue('centralfw' in site.name)
            
        # Test the nodes
        for gw in policy.central_gateway_node.all():
            self.assertIsInstance(gw, GatewayNode)
            self.assertTrue(gw.name.startswith('centralfw'))
            central_site = list(gw.enabled_sites)
            self.assertIsInstance(central_site[0], GatewayTreeNode)
            self.assertFalse(list(gw.disabled_sites))
            gw.delete()

        for gw in policy.satellite_gateway_node.all():
            self.assertIsInstance(gw, GatewayNode)
            self.assertTrue(gw.name.startswith('satellitefw'))
            gw.delete()

        for mobilegw in policy.mobile_gateway_node.all():
            self.assertIsInstance(mobilegw, GatewayNode)

        self.assertIsNotNone(policy.validate())  # Already deleted gw's

        self.assertIsInstance(policy.gateway_tunnel(), list)
        policy.save()
        policy.close()

        # Delete VPN
        policy.delete()

        # Delete FW's
        firewall_central.delete()
        firewall_satellite.delete()

    def test_gateway_setting_profile(self):
        GatewaySettings.create(name='foogateway',
                               negotiation_expiration=1000,
                               negotiation_retry_timer=1000,
                               negotiation_retry_max_number=1000,
                               negotiation_retry_timer_max=1000,
                               certificate_cache_crl_validity=1000,
                               mobike_after_sa_update=False,
                               mobike_before_sa_update=False,
                               mobike_no_rrc=False)
        gateway = GatewaySettings('foogateway')
        fields = ['negotiation_expiration', 'negotiation_retry_timer',
                  'negotiation_retry_max_number', 'negotiation_retry_timer_max',
                  'certificate_cache_crl_validity']
        for field in fields:
            self.assertEqual(gateway.data.get(field), 1000)

        boolfields = ['mobike_after_sa_update', 'mobike_before_sa_update',
                      'mobike_no_rrc']
        for field in boolfields:
            self.assertFalse(gateway.data.get(field))


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()

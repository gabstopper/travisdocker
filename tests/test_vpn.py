'''
Created on Oct 2, 2016

@author: davidlepage
'''
import unittest
from .constants import url, api_key, verify
from smc import session
from smc.vpn.policy import VPNPolicy, CentralGatewayNode, SatelliteGatewayNode
from smc.vpn.elements import ExternalGateway
from smc.elements.collection import describe_vpn, \
    describe_external_gateway, describe_network
from smc.api.common import SMCRequest
from smc.elements.network import Network
from smc.api.exceptions import ElementNotFound, CreatePolicyFailed,\
    CreateElementFailed
from smc.core.engines import Layer3Firewall
from smc.core.engine import Engine

class Test(unittest.TestCase):

    def setUp(self):
        session.login(url=url, api_key=api_key, verify=verify)
        
    def tearDown(self):
        session.logout()
        
    def test_add_vpn_policy(self):
        result = VPNPolicy.create(name='smcpythonVPN', nat=True)
        self.assertIsInstance(result, VPNPolicy)
        self.assertTrue(result.nat)
        
        self.assertRaises(CreatePolicyFailed, lambda: VPNPolicy.create(name='smcpythonVPN'))
    
        # Check VPN Profile
        self.assertIsNotNone(result.vpn_profile)
        
        for x in describe_vpn(name=['smcpythonVPN']):
            self.assertIsNotNone(x.href)
            d = SMCRequest(x.href).delete()
            self.assertEqual(204, d.code)
            
    def test_add_external_gateway_endpoint_and_vpnsite(self):
        for gw in describe_external_gateway(name=['smcpython-externalgw']):
            SMCRequest(gw.href).delete()
            
        result = ExternalGateway.create(name='smcpython-externalgw')
        self.assertIsInstance(result, ExternalGateway)
        
        #For vpn site
        network = Network.create('py4.4.4.0', '4.4.4.0/24')
        
        for x in describe_external_gateway(name=['smcpython-externalgw']):
            self.assertIsNotNone(x.href) #have meta
            e = x.external_endpoint.create('myendpoint', '1.1.1.1') #create endpoint
            self.assertEqual(201, e.code)
            
            # Fail test_external gateway
            self.assertRaises(CreateElementFailed, lambda: ExternalGateway.create('smcpython-externalgw'))
            
            site = x.vpn_site.create('pythonsite', [network.href]) #Cretae vpn site
            self.assertEqual(201, site.code)
            
            #Add an additional network to an existing VPN Site
            network = Network.create('pythonnetwork', '23.23.23.20/24')
            for x in describe_external_gateway(name=['smcpython-externalgw']):
                gw = x
                for sites in gw.vpn_site.all():
                    if sites.name == 'pythonsite':
                        result = sites.modify_attribute(site_element=[network.href])
                        self.assertEqual(200, result.code)
    
            #Disable endpoint (testing modify)
            for z in gw.external_endpoint.all():
                if z.name.startswith('myendpoint'):
                    r = z.modify_attribute(enabled=False)
                    self.assertEqual(200, r.code)
                    
            d = SMCRequest(gw.href).delete()
            self.assertEqual(204, d.code)
            
        for network in describe_network(name=['py4.4.4.0', 'pythonnetwork']):
            n = SMCRequest(network.href).delete()
            self.assertEqual(204, n.code)

    def test_load_non_existant_external_gw(self):
        self.assertRaises(ElementNotFound, lambda: ExternalGateway('wrgrgshfhfdh').describe())
    
    def test_add_VPN_external_and_satellite_gw(self):
        firewall_central = Layer3Firewall.create('centralfw', mgmt_ip='1.1.1.1', 
                                                 mgmt_network='1.1.1.0/24')
        self.assertIsInstance(firewall_central, Engine)
        firewall_satellite = Layer3Firewall.create('satellitefw', mgmt_ip='2.2.2.2',
                                                   mgmt_network='2.2.2.0/24')
        self.assertIsInstance(firewall_satellite, Engine)
        
        policy = VPNPolicy.create(name='tmptestvpn')
        self.assertIsInstance(policy, VPNPolicy)
        
        self.assertTrue(VPNPolicy.add_internal_gateway_to_vpn(firewall_central.internal_gateway.href, 
                                                              vpn_policy='tmptestvpn', 
                                                              vpn_role='central'))
        self.assertTrue(VPNPolicy.add_internal_gateway_to_vpn(firewall_satellite.internal_gateway.href, 
                                                              vpn_policy='tmptestvpn', 
                                                              vpn_role='satellite'))
    
        policy.open()
        # Test the nodes
        for gw in policy.central_gateway_node.all():
            self.assertIsInstance(gw, CentralGatewayNode)
            self.assertTrue(gw.name.startswith('centralfw'))
            self.assertIn(gw.delete().code, [200, 204])
        
        for gw in policy.satellite_gateway_node.all():
            self.assertIsInstance(gw, SatelliteGatewayNode)
            self.assertTrue(gw.name.startswith('satellitefw'))
            self.assertIn(gw.delete().code, [200, 204])
    
        self.assertIsNotNone(policy.validate().get('value'), None) #Already deleted gw's
        policy.save()
        policy.close()
        
        # Delete VPN
        self.assertEqual(204, policy.delete().code)
        
        # Delete FW's
        self.assertEqual(204, firewall_central.delete().code)
        self.assertEqual(204, firewall_satellite.delete().code)
            
if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
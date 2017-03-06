'''
Created on Oct 2, 2016

@author: davidlepage
'''
import unittest
from constants import url, api_key, verify
from smc import session
from smc.vpn.policy import VPNPolicy, CentralGatewayNode, SatelliteGatewayNode,\
    MobileGatewayNode
from smc.vpn.elements import ExternalGateway
from smc.elements.collection import describe_vpn, \
    describe_external_gateway, describe_network
from smc.elements.network import Network
from smc.api.exceptions import ElementNotFound, CreatePolicyFailed,\
    CreateElementFailed, PolicyCommandFailed
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
        
        with self.assertRaises(CreatePolicyFailed):
            VPNPolicy.create(name='smcpythonVPN')
    
        # Check VPN Profile
        self.assertIsNotNone(result.vpn_profile)
        
        for x in describe_vpn(name=['smcpythonVPN']):
            self.assertTrue(x.href.startswith('http'))
            x.delete()
        
    def test_add_external_gateway_endpoint_and_vpnsite(self):
        for gw in describe_external_gateway(name=['smcpython-externalgw']):
            gw.delete()
            
        result = ExternalGateway.create(name='smcpython-externalgw')
        self.assertIsInstance(result, ExternalGateway)
        
        #For vpn site
        network = Network.create('py4.4.4.0', '4.4.4.0/24')
        
        for x in describe_external_gateway(name=['smcpython-externalgw']):
            self.assertIsNotNone(x.href) #have meta
            e = x.external_endpoint.create('myendpoint', '1.1.1.1') #create endpoint
            self.assertTrue(e.startswith('http'))
            
            #Invalid endpoint
            with self.assertRaises(CreateElementFailed):
                x.external_endpoint.create('myendpoint', '1.1.1.1a')
            
            # Fail test_external gateway
            with self.assertRaises(CreateElementFailed):
                ExternalGateway.create('smcpython-externalgw')
            
            site = x.vpn_site.create('pythonsite', [network]) #Cretae vpn site
            self.assertTrue(site.startswith('http'))
            
            with self.assertRaises(CreateElementFailed):
                x.vpn_site.create('poosite', ['http://1.1.1.1'])
            
            #Add an additional network to an existing VPN Site
            network = Network.create('pythonnetwork', '23.23.23.0/24')
            for x in describe_external_gateway(name=['smcpython-externalgw']):
                gw = x
                for sites in gw.vpn_site.all():
                    if sites.name == 'pythonsite':
                        result = sites.modify_attribute(site_element=[network])
                        self.assertIsNone(result)
    
            #Disable endpoint (testing modify)
            for z in gw.external_endpoint.all():
                if z.name.startswith('myendpoint'):
                    r = z.modify_attribute(enabled=False)
                    self.assertIsNone(r)
            
            gw.delete()        
            
        for network in describe_network(name=['py4.4.4.0', 'pythonnetwork']):
            network.delete()

    def test_load_non_existant_external_gw(self):
        with self.assertRaises(ElementNotFound):
            ExternalGateway('wrgrgshfhfdh').describe()
    
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
        
        # Invalid vpn policy
        self.assertFalse(VPNPolicy.add_internal_gateway_to_vpn(firewall_central.internal_gateway.href,
                                                               vpn_policy='foobar'))
        
        with self.assertRaises(PolicyCommandFailed):
            policy.close()
            
        policy.open()
        # Test the nodes
        for gw in policy.central_gateway_node.all():
            self.assertIsInstance(gw, CentralGatewayNode)
            self.assertTrue(gw.name.startswith('centralfw'))
            gw.delete()
            
        for gw in policy.satellite_gateway_node.all():
            self.assertIsInstance(gw, SatelliteGatewayNode)
            self.assertTrue(gw.name.startswith('satellitefw'))
            gw.delete()
        
        for mobilegw in policy.mobile_gateway_node.all():
            self.assertIsInstance(mobilegw, MobileGatewayNode)
            
        self.assertIsNotNone(policy.validate().get('value'), None) #Already deleted gw's
        
        self.assertIsInstance(policy.gateway_tunnel(), list)
        policy.save()
        policy.close()
        
        # Delete VPN
        policy.delete()
        
        # Delete FW's
        firewall_central.delete()
        firewall_satellite.delete()
            
if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
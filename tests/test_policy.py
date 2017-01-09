'''
Created on Oct 20, 2016

@author: davidlepage
'''
import time
import unittest
from constants import url, api_key, verify
from smc import session
from smc.policy.layer3 import FirewallPolicy, FirewallTemplatePolicy
from smc.api.exceptions import LoadPolicyFailed, MissingRequiredInput,\
    TaskRunFailed, CreatePolicyFailed
from smc.policy.rule import IPv4Rule, IPv4Layer2Rule, EthernetRule
from smc.vpn.policy import VPNPolicy
from smc.policy.layer2 import Layer2Policy
from smc.api.common import SMCRequest
from smc.elements.other import LogicalInterface
from smc.policy.ips import IPSPolicy
from smc.elements.collection import describe_tcp_service,\
    describe_file_filtering_policy
from smc.core.engines import Layer3Firewall
from smc.administration.tasks import task_history, task_status
from smc.policy.file_filtering import FileFilteringRule

class Test(unittest.TestCase):

    def setUp(self):
        session.login(url=url, api_key=api_key, verify=verify, timeout=30)
        
    def tearDown(self):
        try:
            session.logout()
        except SystemExit:
            pass


    def test_FW_bad_template_Policy(self):
        self.assertRaises(LoadPolicyFailed, lambda: FirewallPolicy.create(name='myfw', template='foo'))
                          
    def test_FW_create_good_policy(self):
        policy = FirewallPolicy.create(name='myfoopolicy', template='Firewall Inspection Template')
        self.assertIsInstance(policy, FirewallPolicy)
        # Fail
        self.assertRaises(CreatePolicyFailed, lambda: FirewallPolicy.create(name='myfoopolicy', 
                                                                            template='Firewall Inspection Template'))
        # Get the template
        self.assertIsInstance(policy.template, FirewallTemplatePolicy)
        
        self.assertIn(policy.delete().code, [200, 204])
        
    def test_FW_validate_fw_rule_creation(self):
        policy = FirewallPolicy.create(name='myfoopolicy', template='Firewall Inspection Template')
        self.assertIsInstance(policy, FirewallPolicy)
        rule = policy.fw_ipv4_access_rules.create(name='myrule', sources='any', action='somebadvalue')
        self.assertEqual(201, rule.code)
        for rule in policy.fw_ipv4_access_rules.all():
            self.assertIsInstance(rule, IPv4Rule)
            self.assertEqual(rule.name, 'myrule')
            self.assertEqual(204, rule.delete().code)
        self.assertEqual(204, policy.delete().code)
    
    def test_FW_rule_with_outliers(self):
        from smc.elements.network import Host
        policy = FirewallPolicy.create(name='myfoopolicy', template='Firewall Inspection Template')
        self.assertIsInstance(policy, FirewallPolicy)
        
        host = Host.create('asourcehost', '1.1.1.1').href
        services = [service.href for service in describe_tcp_service(name=['HTTP'])]
        # Source href's provided
        rule = policy.fw_ipv4_access_rules.create(name='myrule', sources=[host], services=services)
        self.assertEqual(201, rule.code)
        
        # Rule with no sources
        rule = policy.fw_ipv4_access_rules.create(name='myrule', sources=[host], services=services)
        self.assertEqual(201, rule.code)
        
        self.assertEqual(204, policy.delete().code)
        self.assertEqual(204, Host('asourcehost').delete().code)
        
    def test_FW_validate_fw_rule_with_vpn(self):
        policy = FirewallPolicy.create(name='myfoopolicy', template='Firewall Inspection Template')
        self.assertIsInstance(policy, FirewallPolicy)
        
        vpn = VPNPolicy.create(name='foovpn')
        self.assertIsInstance(vpn, VPNPolicy)
        
        #Bad VPN Name
        self.assertRaises(MissingRequiredInput, 
                          lambda: policy.fw_ipv4_access_rules.create(name='myvpnrule', 
                                        sources='any', 
                                        destinations='any', 
                                        services='any',
                                        action='enforce_vpn',
                                        vpn_policy='foo'))
        
        #Missing VPN Name
        self.assertRaises(MissingRequiredInput, 
                          lambda: policy.fw_ipv4_access_rules.create(name='myvpnrule', 
                                        sources='any', 
                                        destinations='any', 
                                        services='any',
                                        action='enforce_vpn'))
        
        result = policy.fw_ipv4_access_rules.create(name='myvpnrule', 
                                                    sources='any', 
                                                    destinations='any', 
                                                    services='any',
                                                    action='enforce_vpn',
                                                    vpn_policy='foovpn')
        self.assertEqual(201, result.code)
        
        for rule in policy.fw_ipv4_access_rules.all():
            self.assertIsInstance(rule, IPv4Rule)
            self.assertEqual(rule.name, 'myvpnrule')
            self.assertEqual(204, rule.delete().code)
        self.assertEqual(204, policy.delete().code)
        self.assertEqual(204, SMCRequest(vpn.href).delete().code)
         
    def test_L2FW_bad_template_Policy(self):
        self.assertRaises(LoadPolicyFailed, lambda: Layer2Policy.create(name='myfw', template='foo'))
                          
    def test_L2FW_create_good_policy(self):
        policy = Layer2Policy.create(name='layer2foo', template='Layer 2 Firewall Inspection Template')
        self.assertIsInstance(policy, Layer2Policy)
        self.assertEqual(204, policy.delete().code)
        
    def test_L2FW_validate_fw_rule_creation(self):
        policy = Layer2Policy.create(name='layer2foo', template='Layer 2 Firewall Inspection Template')
        self.assertIsInstance(policy, Layer2Policy)
        rule = policy.layer2_ipv4_access_rules.create(name='myrule', sources='any')
        self.assertEqual(201, rule.code)
        for rule in policy.layer2_ipv4_access_rules.all():
            self.assertIsInstance(rule, IPv4Layer2Rule)
            self.assertEqual(rule.name, 'myrule')
            self.assertEqual(204, rule.delete().code)
        
        # Rule with incorrect action
        rule = policy.layer2_ipv4_access_rules.create(name='myrule', sources='any', action='duh')
        self.assertEqual(201, rule.code)
        
        # Rule with non-existant logical interface
        self.assertRaises(MissingRequiredInput, lambda: policy.layer2_ipv4_access_rules.create(name='myrule', logical_interfaces=['foo']))
        
        self.assertEqual(204, policy.delete().code)
        
    def test_L2FW_validate_fw_ethernet_rule_creation(self):
        policy = Layer2Policy.create(name='layer2foo', template='Layer 2 Firewall Inspection Template')
        self.assertIsInstance(policy, Layer2Policy)
        rule = policy.layer2_ethernet_rules.create(name='myethernetrule', 
                                                   sources='any', 
                                                   destinations='any', 
                                                   services='any')
        self.assertEqual(201, rule.code, rule.msg)
        for rule in policy.layer2_ethernet_rules.all():
            self.assertIsInstance(rule, EthernetRule)
            self.assertEqual(rule.name, 'myethernetrule')
            self.assertEqual(204, rule.delete().code)
        self.assertEqual(204, policy.delete().code)
        
    def test_L2FW_validate_fw_ethernet_rule_with_logical_intf(self):
        policy = Layer2Policy.create(name='layer2foo', template='Layer 2 Firewall Inspection Template')
        self.assertIsInstance(policy, Layer2Policy)
        
        logical = LogicalInterface.create(name='logical_foo')
        self.assertEqual(201, logical.code, logical.msg)
        rule = policy.layer2_ethernet_rules.create(name='myethernetrule', 
                                                   sources='any', 
                                                   destinations='any', 
                                                   services='any',
                                                   logical_interfaces=['logical_foo'])
        self.assertEqual(201, rule.code, rule.msg)
        for rule in policy.layer2_ethernet_rules.all():
            self.assertIsInstance(rule, EthernetRule)
            self.assertEqual(rule.name, 'myethernetrule')
            self.assertEqual(204, rule.delete().code)
        self.assertEqual(204, policy.delete().code)
        self.assertEqual(204, SMCRequest(logical.href).delete().code)
            
    def test_IPS_bad_template_Policy(self):
        self.assertRaises(LoadPolicyFailed, lambda: IPSPolicy.create(name='myfw', template='foo'))
                          
    def test_IPS_create_good_policy(self):
        policy = IPSPolicy.create(name='myfoopolicy', template='High-Security IPS Template')
        self.assertIsInstance(policy, IPSPolicy)
        self.assertEqual(204, policy.delete().code)
              
    def test_IPS_validate_fw_rule_creation(self):
        policy = IPSPolicy.create(name='layer2foo', template='High-Security IPS Template')
        self.assertIsInstance(policy, IPSPolicy)
        rule = policy.ips_ipv4_access_rules.create(name='myrule', sources='any')
        self.assertEqual(201, rule.code)
        for rule in policy.ips_ipv4_access_rules.all():
            self.assertIsInstance(rule, IPv4Layer2Rule)
            self.assertEqual(rule.name, 'myrule')
            self.assertEqual(204, rule.delete().code)
        self.assertEqual(204, policy.delete().code)
        
    def test_IPS_validate_fw_ethernet_rule_creation(self):
        policy = IPSPolicy.create(name='layer2foo', template='High-Security IPS Template')
        self.assertIsInstance(policy, IPSPolicy)
        # Policy - notice action is not correct, will default to allow
        rule = policy.ips_ethernet_rules.create(name='myethernetrule', 
                                                sources='any',
                                                action='foo', 
                                                destinations='any', 
                                                services='any')
        self.assertEqual(201, rule.code, rule.msg)
        for rule in policy.ips_ethernet_rules.all():
            self.assertIsInstance(rule, EthernetRule)
            self.assertEqual(rule.name, 'myethernetrule')
            action = rule.describe().get('action')
            self.assertEqual(action.get('action'), 'allow')
            self.assertEqual(204, rule.delete().code)
            
        self.assertEqual(204, policy.delete().code)
        
    def test_IPS_validate_fw_ethernet_rule_with_logical_intf(self):
        policy = IPSPolicy.create(name='layer2foo', template='High-Security IPS Template')
        self.assertIsInstance(policy, IPSPolicy)
        
        logical = LogicalInterface.create(name='logical_foo')
        self.assertEqual(201, logical.code, logical.msg)
        rule = policy.ips_ethernet_rules.create(name='myethernetrule', 
                                                sources='any', 
                                                destinations='any', 
                                                services='any',
                                                logical_interfaces=['logical_foo'])
        self.assertEqual(201, rule.code, rule.msg)
        for rule in policy.ips_ethernet_rules.all():
            self.assertIsInstance(rule, EthernetRule)
            self.assertEqual(rule.name, 'myethernetrule')
            self.assertEqual(204, rule.delete().code)
        self.assertEqual(204, policy.delete().code)
        self.assertEqual(204, SMCRequest(logical.href).delete().code)

    def test_NAT_operations(self):
        from smc.elements.network import Host
        
        policy = FirewallPolicy.create(name='apitestpolicy', template='Firewall Inspection Template')
        host = Host.create('nathost', '1.1.1.1').href
        nat = Host.create('sourcenat', '2.2.2.2').href
        
        # Source NAT using port restrictions
        r = policy.fw_ipv4_nat_rules.create(name='dstandsrcnat', 
                                        sources='any', 
                                        destinations=[host],
                                        services='any',
                                        dynamic_src_nat={'ip_descriptor': '2.2.2.2',
                                                         'min_port': 30000,
                                                         'max_port': 35000})
        self.assertIn(r.code, [200,201])
        
        #Dest NAT by IP
        r = policy.fw_ipv4_nat_rules.create(name='dstnat', 
                                        sources='any', 
                                        destinations=[host],
                                        services='any',
                                        static_dst_nat={'translated_value': {
                                                            'ip_descriptor': '3.3.3.3'}})     
        self.assertIn(r.code, [200,201])
        
        # Source and Dest NAT
        r = policy.fw_ipv4_nat_rules.create(name='dstandsrcnat', 
                                        sources='any', 
                                        destinations=[nat],
                                        services='any',
                                        dynamic_src_nat={'ip_descriptor': '2.2.2.2'},
                                        static_dst_nat={'translated_value': {
                                                            'ip_descriptor': '3.3.3.3'}})
        self.assertIn(r.code, [200,201])
        # Dest NAT by element
        r = policy.fw_ipv4_nat_rules.create(name='dstandsrcnat', 
                                        sources='any', 
                                        destinations=[host],
                                        services='any',
                                        dynamic_src_nat={'ip_descriptor': '2.2.2.2'},
                                        static_dst_nat={'translated_value': {
                                                            'element': nat}}) 
        self.assertIn(r.code, [200,201])              
        
        r = policy.fw_ipv4_nat_rules.create(name='nonatrule', 
                                            sources='any', 
                                            destinations='any', 
                                            services='any')
        self.assertIn(r.code, [200,201])
        
        # Static source NAT, this is broken in SMC 6.1.1 #TODO:
        r = policy.fw_ipv4_nat_rules.create(name='srcdstnat', 
                                        sources=[host], 
                                        destinations='any',
                                        services='any',
                                        static_src_nat={'ip_descriptor': '3.3.3.3'}) 
        self.assertIn(r.code, [400])
                                  
        self.assertEqual(policy.delete().code, 204)
        
        Host('nathost').delete()
        Host('sourcenat').delete()
        
    def test_policy_upload(self):
        # This will just sit in the task queue because the engine will not be initialized, but still tests
        # that policy upload from policy itself triggers properly
        policy = FirewallPolicy.create(name='apitestpolicy', template='Firewall Inspection Template')
        engine = Layer3Firewall.create(name='temppolicy', mgmt_ip='1.1.1.1', mgmt_network='1.1.1.0/24')
        #self.assertRaises(TaskRunFailed, lambda: policy.upload(engine.name))
        task = next(policy.upload(engine.name, wait_for_finish=False))
        self.assertTrue(task.startswith('http'))
        time.sleep(5)
        
        # Force failure, engine does not exist
        self.assertRaises(TaskRunFailed, lambda: policy.upload('bogusfw'))
        
        # Abort queued task then delete policy
        for tasks in task_history():
            if tasks.follower == task and tasks.in_progress:
                result = tasks.abort()
                # 204 delete successful, 400 if the operation is already being aborted
                self.assertIn(result.code, [204, 400])
        
        status = task_status(task)
        for _ in range(1, 5):
            if status.in_progress:
                print("Status still in progress: %s" % vars(status))
                self.assertIn(status.abort().code, [204, 400])
            else:
                print("Status not progress: %s" % vars(status))
                break
            
        self.assertEqual(engine.delete().code, 204)
        self.assertEqual(policy.delete().code, 204)
    
    @unittest.skip("tmp")     
    def test_file_filtering_policy(self):
        # Not fully implemented
        policy = describe_file_filtering_policy()
        if policy:
            for rules in policy[0].file_filtering_rules.all():
                self.assertIsInstance(rules, FileFilteringRule)
            
        
if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
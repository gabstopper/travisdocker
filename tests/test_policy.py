'''
Created on Oct 20, 2016

@author: davidlepage
'''
import time
import unittest
from .constants import url, api_key, verify,\
    is_min_required_smc_version
from smc.administration.system import System
from smc import session
from smc.policy.layer3 import FirewallPolicy, FirewallTemplatePolicy
from smc.api.exceptions import LoadPolicyFailed, MissingRequiredInput,\
    TaskRunFailed, CreatePolicyFailed, InvalidRuleValue, CreateRuleFailed,\
    DeleteElementFailed
from smc.policy.rule import IPv4Rule, IPv4Layer2Rule, EthernetRule
from smc.policy.rule_nat import IPv4NATRule
from smc.vpn.policy import VPNPolicy
from smc.policy.layer2 import Layer2Policy, Layer2TemplatePolicy
from smc.api.common import SMCRequest
from smc.elements.other import LogicalInterface
from smc.policy.ips import IPSPolicy, IPSTemplatePolicy
from smc.elements.collection import describe_tcp_service,\
    describe_file_filtering_policy, describe_application_situation
from smc.core.engines import Layer3Firewall
from smc.administration.tasks import task_history, task_status
from smc.policy.file_filtering import FileFilteringRule
from smc.policy.rule_elements import AuthenticationOptions, LogOptions
from smc.elements.network import Host
from smc.base.model import Element

class Test(unittest.TestCase):

    def setUp(self):
        session.login(url=url, api_key=api_key, verify=verify, timeout=30)
        
    def tearDown(self):
        try:
            session.logout()
        except SystemExit:
            pass

    def test_FW_bad_template_Policy(self):
        with self.assertRaises(LoadPolicyFailed):
            FirewallPolicy.create(name='myfw', template='foo')
                          
    def test_FW_create_good_policy_failed_rule_create(self):
        policy = FirewallPolicy.create(name='myfoopolicy', 
                                       template='Firewall Inspection Template')
        self.assertIsInstance(policy, FirewallPolicy)
        # Fail
        with self.assertRaises(CreatePolicyFailed):
            FirewallPolicy.create(name='myfoopolicy', 
                                  template='Firewall Inspection Template')
            
        # Get the template
        self.assertIsInstance(policy.template, FirewallTemplatePolicy)
        
        service = describe_tcp_service('HTTPS')
        application = describe_application_situation('100Bao')
        
        with self.assertRaises(CreateRuleFailed):
            policy.fw_ipv4_access_rules.create(name='bogus', 
                                               sources='any', 
                                               destinations='any', 
                                               services=service+application)
        
        self.assertIsNone(policy.force_unlock())
        policy.delete()
    
    def test_modify_rules(self):
        policy = FirewallPolicy.create(name='myfoopolicy', 
                                       template='Firewall Inspection Template')
        Host.create(name='foobar', address='1.1.1.1')
        host = Host('foobar')
        policy.fw_ipv4_access_rules.create(name='myrule', 
                                           sources=[host], 
                                           action='somebadvalue')
        
        for rule in policy.fw_ipv4_access_rules.all():
            if rule.name == 'myrule':
                self.assertEqual(rule.action.action, 'allow')
                self.assertIsInstance(rule.authentication_options, AuthenticationOptions)
                self.assertIsInstance(rule.options, LogOptions)
                
                self.assertFalse(rule.is_disabled)
                self.assertEqual(rule.parent_policy, 'myfoopolicy')
                self.assertTrue(rule.destinations.is_none)
                self.assertTrue(rule.services.is_none)
                self.assertFalse(rule.services.all())
                for source in rule.sources.all():
                    self.assertEqual(source.name, 'foobar')
                    
                rule.disable()    
                rule.comment = 'mycomment'
                rule.services.set_any()
                rule.save()
                self.assertEqual(rule.comment, 'mycomment')
                rule.enable()
                rule.save()
                self.assertFalse(rule.is_disabled)
                rule.delete()
        
        Host('foobar').delete()
        
        policy.fw_ipv4_access_rules.create(name='myrule', 
                                           sources='any', 
                                           destinations=[Host('badhost')], 
                                           action='somebadvalue')
        
        # Will be returned as type "Element" 
        engine = Layer3Firewall.create(name='tmpfw', 
                                       mgmt_ip='1.1.1.1', 
                                       mgmt_network='1.1.1.0/24')
        
        for rule in policy.fw_ipv4_access_rules.all():
            if rule.name == 'myrule':
                self.assertTrue(rule.destinations.is_none)
                self.assertTrue(rule.sources.is_any)
                rule.destinations.add(Host('blah'))
                rule.save()
                self.assertFalse(rule.destinations.is_none)
                rule.destinations.add_many([Host('boo'), engine])
                rule.save()
                for x in rule.destinations.all():
                    self.assertIsInstance(x, Element)
        
        policy.delete()
        time.sleep(3)            
        engine.delete()        
            
    def test_FW_validate_fw_rule_creation(self):
        # Validate rules
        policy = FirewallPolicy.create(name='myfoopolicy', template='Firewall Inspection Template')
        self.assertIsInstance(policy, FirewallPolicy)
        
        policy.fw_ipv4_access_rules.create(name='myrule', sources='any', action='somebadvalue')
        
        for rule in policy.fw_ipv4_access_rules.all():
            self.assertIsInstance(rule, IPv4Rule)
            self.assertEqual(rule.name, 'myrule')
            rule.delete()
        policy.delete()
    
    def test_FW_rule_with_outliers(self):
        
        policy = FirewallPolicy.create(name='myfoopolicy', template='Firewall Inspection Template')
        self.assertIsInstance(policy, FirewallPolicy)
        
        host = Host.create('asourcehost', '1.1.1.1')
        services = [service.href for service in describe_tcp_service(name=['HTTP'])]
        # Source href's provided
        policy.fw_ipv4_access_rules.create(name='myrule', sources=[host], services=services)
        
        # Rule with no sources
        policy.fw_ipv4_access_rules.create(name='myrule', sources=[host], services=services)
        
        policy.delete()
        Host('asourcehost').delete()
        
    def test_FW_validate_fw_rule_with_vpn(self):
        policy = FirewallPolicy.create(name='myfoopolicy', template='Firewall Inspection Template')
        self.assertIsInstance(policy, FirewallPolicy)
        
        vpn = VPNPolicy.create(name='foovpn')
        self.assertIsInstance(vpn, VPNPolicy)
        
        #Bad VPN Name
        with self.assertRaises(MissingRequiredInput):
            policy.fw_ipv4_access_rules.create(name='myvpnrule', 
                                        sources='any', 
                                        destinations='any', 
                                        services='any',
                                        action='enforce_vpn',
                                        vpn_policy='foo')
        
        #Missing VPN Name
        with self.assertRaises(MissingRequiredInput):
            policy.fw_ipv4_access_rules.create(name='myvpnrule', 
                                               sources='any', 
                                               destinations='any', 
                                               services='any',
                                               action='enforce_vpn')
        
        Host.create(name='mydest', address='1.1.1.1')
        dest = Host('mydest')
        policy.fw_ipv4_access_rules.create(name='myvpnrule', 
                                           sources='any', 
                                           destinations=[dest], 
                                           services='any',
                                           action='enforce_vpn',
                                           vpn_policy='foovpn')
        
        for rule in policy.fw_ipv4_access_rules.all():
            self.assertIsInstance(rule, IPv4Rule)
            self.assertEqual(rule.name, 'myvpnrule')
            rule.delete()
            
        #IPv6 Rules    
        Host.create(name='myipv6', ipv6_address='2001:0db8:85a3:0000:0000:8a2e:0370:7334')
        policy.fw_ipv6_access_rules.create(name='myrule', 
                                           sources=[Host('myipv6')], 
                                           destinations='any', 
                                           services='any', 
                                           action='discard')
        
        policy.delete()
        Host('myipv6').delete()
        self.assertEqual(204, SMCRequest(vpn.href).delete().code)
         
    def test_L2FW_bad_template_Policy(self):
        with self.assertRaises(LoadPolicyFailed):
            Layer2Policy.create(name='myfw', template='foo')
                          
    def test_L2FW_create_good_policy_failed_rule_create(self):
        policy = Layer2Policy.create(name='layer2foo', 
                                     template='Layer 2 Firewall Inspection Template')
        self.assertIsInstance(policy, Layer2Policy)
        
        # Fail create due to existing policy
        with self.assertRaises(CreatePolicyFailed):
            Layer2Policy.create(name='layer2foo', 
                                template='Layer 2 Firewall Inspection Template')
        
        # Validate template
        template = policy.template
        self.assertIsInstance(template, Layer2TemplatePolicy)
        self.assertEqual(template.name, 'Layer 2 Firewall Inspection Template')
        
        # Invalid to add a service and application together    
        service = describe_tcp_service('HTTPS')
        application = describe_application_situation('100Bao')
        
        with self.assertRaises(CreateRuleFailed):
            policy.layer2_ipv4_access_rules.create(name='bogus', 
                                                   sources='any', 
                                                   destinations='any', 
                                                   services=service+application)
            
        policy.delete()
        
    def test_L2FW_validate_fw_rule_creation(self):
        policy = Layer2Policy.create(name='layer2foo', 
                                     template='Layer 2 Firewall Inspection Template')
        self.assertIsInstance(policy, Layer2Policy)
        
        policy.layer2_ipv4_access_rules.create(name='myrule', sources='any')
        
        for rule in policy.layer2_ipv4_access_rules.all():
            self.assertIsInstance(rule, IPv4Layer2Rule)
            self.assertEqual(rule.name, 'myrule')
            rule.delete()
        
        # Rule with incorrect action
        policy.layer2_ipv4_access_rules.create(name='myrule', 
                                               sources='any',
                                               action='duh')
        
        # Search should return right object time
        rules = policy.search_rule('myrule')
        self.assertIsInstance(rules, list)
        self.assertIsInstance(rules[0], IPv4Layer2Rule)
        
        # Rule with non-existant logical interface
        with self.assertRaises(MissingRequiredInput):
            policy.layer2_ipv4_access_rules.create(name='myrule', 
                                                   logical_interfaces=['foo'])
            
        policy.delete()
        
    def test_L2FW_validate_fw_ethernet_rule_creation(self):
        policy = Layer2Policy.create(name='layer2foo', 
                                     template='Layer 2 Firewall Inspection Template')
        self.assertIsInstance(policy, Layer2Policy)
        
        policy.layer2_ethernet_rules.create(name='myethernetrule', 
                                            sources='any', 
                                            destinations='any', 
                                            services='any')
        
        for rule in policy.layer2_ethernet_rules.all():
            self.assertIsInstance(rule, EthernetRule)
            self.assertEqual(rule.name, 'myethernetrule')
            rule.delete()
        policy.delete()
        
    def test_L2FW_validate_fw_ethernet_rule_with_logical_intf(self):
        policy = Layer2Policy.create(name='layer2foo', 
                                     template='Layer 2 Firewall Inspection Template')
        self.assertIsInstance(policy, Layer2Policy)
        
        logical = LogicalInterface.create(name='logical_foo')
        self.assertTrue(logical.startswith('http'))
        policy.layer2_ethernet_rules.create(name='myethernetrule', 
                                            sources='any', 
                                            destinations='any', 
                                            services='any',
                                            logical_interfaces=['logical_foo'])
        
        for rule in policy.layer2_ethernet_rules.all():
            self.assertIsInstance(rule, EthernetRule)
            self.assertEqual(rule.name, 'myethernetrule')
            rule.delete()
        policy.delete()
        self.assertEqual(204, SMCRequest(logical).delete().code)
            
    def test_IPS_bad_template_Policy(self):
        with self.assertRaises(LoadPolicyFailed):
            IPSPolicy.create(name='myfw', template='foo')
                          
    def test_IPS_create_good_policy(self):
        policy = IPSPolicy.create(name='myfoopolicy', 
                                  template='High-Security IPS Template')
        self.assertIsInstance(policy, IPSPolicy)
        
        # Valid only for SMC < 6.1
        self.assertIsNone(policy.open())
        
        with self.assertRaises(CreatePolicyFailed):
            IPSPolicy.create(name='myfoopolicy', 
                             template='High-Security IPS Template')
        
        template = policy.template
        self.assertIsInstance(template, IPSTemplatePolicy)
        self.assertEqual(template.name, 'High-Security IPS Template')
        
        # Only valid for SMC < 6.1
        self.assertIsNone(policy.save())
        
        policy.delete()
              
    def test_IPS_validate_fw_rule_creation(self):
        policy = IPSPolicy.create(name='layer2foo', 
                                  template='High-Security IPS Template')
        self.assertIsInstance(policy, IPSPolicy)
        policy.ips_ipv4_access_rules.create(name='myrule', sources='any')
        
        # Search back the rule, should be list and IPv4Layer2Rule
        rules = policy.search_rule('myrule')
        self.assertIsInstance(rules, list)
        self.assertIsInstance(rules[0], IPv4Layer2Rule)
        
        for rule in policy.ips_ipv4_access_rules.all():
            self.assertIsInstance(rule, IPv4Layer2Rule)
            self.assertEqual(rule.name, 'myrule')
            rule.delete()
            
        policy.delete()
        
    def test_IPS_validate_fw_ethernet_rule_creation_with_fail(self):
        policy = IPSPolicy.create(name='layer2foo', template='High-Security IPS Template')
        self.assertIsInstance(policy, IPSPolicy)
        # Policy - notice action is not correct, will default to allow
        policy.ips_ethernet_rules.create(name='myethernetrule', 
                                         sources='any',
                                         action='foo', 
                                         destinations='any', 
                                         services='any')
        
        for rule in policy.ips_ethernet_rules.all():
            self.assertIsInstance(rule, EthernetRule)
            self.assertEqual(rule.name, 'myethernetrule')
            action = rule.data.get('action')
            self.assertEqual(action.get('action'), 'allow')
            rule.delete()
        
        service = describe_tcp_service('HTTPS')
        application = describe_application_situation('100Bao')
        
        with self.assertRaises(CreateRuleFailed):
            policy.ips_ethernet_rules.create(name='bogus', 
                                             sources='any', 
                                             destinations='any', 
                                             services=service+application)
                
        policy.delete()
        
    def test_IPS_validate_fw_ethernet_rule_with_logical_intf(self):
        policy = IPSPolicy.create(name='layer2foo', template='High-Security IPS Template')
        self.assertIsInstance(policy, IPSPolicy)
        
        logical = LogicalInterface.create(name='logical_foo')
        self.assertTrue(logical.startswith('http'))
        policy.ips_ethernet_rules.create(name='myethernetrule', 
                                         sources='any', 
                                         destinations='any', 
                                         services='any',
                                         logical_interfaces=['logical_foo'])
        
        # Search policy for this rule, should return Ethernet Rule
        rule = policy.search_rule('myethernetrule')
        self.assertIsInstance(rule, list)
        self.assertIsInstance(rule[0], EthernetRule)
        
        for rule in policy.ips_ethernet_rules.all():
            self.assertIsInstance(rule, EthernetRule)
            self.assertEqual(rule.name, 'myethernetrule')
            rule.delete()
        policy.delete()
        self.assertEqual(204, SMCRequest(logical).delete().code)
        
    def test_NATRules(self):
        
        policy = FirewallPolicy.create(name='apitestpolicy', 
                                       template='Firewall Inspection Template')
        
        Host.create('nathost', address='1.1.1.1')
        Host.create('sourcenat', address='2.2.2.2')
        
        engine = Layer3Firewall.create(name='natfw', 
                                       mgmt_ip='1.1.1.1', 
                                       mgmt_network='1.1.1.0/24')
        
        # Source NAT using port restrictions
        policy.fw_ipv4_nat_rules.create(name='dynsrcnat', 
                                        sources='any', 
                                        destinations=[Host('nathost')],
                                        services='any',
                                        dynamic_src_nat='2.2.2.2',
                                        dynamic_src_nat_ports=(30000,35000))
        
        #Dest NAT by IP
        policy.fw_ipv4_nat_rules.create(name='dstnat', 
                                        sources='any', 
                                        destinations=[Host('nathost')],
                                        services='any',
                                        static_dst_nat='3.3.3.3')
    
        # Destination field cannot be any or none with dest NAT    
        with self.assertRaises(InvalidRuleValue):
            policy.fw_ipv4_nat_rules.create(name='foo', 
                                            sources='any', 
                                            destinations='any',
                                            services='any',
                                            static_dst_nat='3.3.3.3')
             
        # Source and Dest NAT
        policy.fw_ipv4_nat_rules.create(name='dstandsrcnat', 
                                        sources='any', 
                                        destinations=[Host('sourcenat')],
                                        services='any',
                                        dynamic_src_nat='5.5.5.5',
                                        static_dst_nat='3.3.3.3')
       
        policy.fw_ipv4_nat_rules.create(name='nonatrule', 
                                        sources='any', 
                                        destinations='any', 
                                        services='any')
        
        system = System()
        
        # Static src NAT
        if is_min_required_smc_version(system.smc_version, '6.1.2'):
            policy.fw_ipv4_nat_rules.create(name='static_src_nat',
                                            sources=[Host('sourcenat')],
                                            destinations='any',
                                            static_src_nat='1.1.1.1')
        else:
            with self.assertRaises(CreateRuleFailed):
                policy.fw_ipv4_nat_rules.create(name='static_src_nat',
                                                sources=[Host('sourcenat')],
                                                destinations='any',
                                                static_src_nat='1.1.1.1')
        # Invalid rule
        with self.assertRaises(CreateRuleFailed):
            policy.fw_ipv4_nat_rules.create(name='foo', 
                                    sources='any', 
                                    destinations=['any'],
                                    services='any',
                                    static_dst_nat='1.1.1.1')
            
        for rule in policy.fw_ipv4_nat_rules.all():
            self.assertIsInstance(rule, IPv4NATRule)
            if rule.name == 'dynsrcnat':
                self.assertEqual(rule.dynamic_src_nat.translated_value, '2.2.2.2')
                self.assertIsNone(rule.dynamic_src_nat.original_value) # Not valid for dyn src nat
                self.assertEqual(rule.dynamic_src_nat.translated_ports, (30000,35000))
            elif rule.name == 'dstnat':
                if is_min_required_smc_version(system.smc_version, '6.1.2'):
                    self.assertEqual(rule.static_dst_nat.translated_value, '3.3.3.3')
                    self.assertEqual(rule.static_dst_nat.original_value, '1.1.1.1')
                else: #Version 6.1.1
                    self.assertEqual(rule.static_dst_nat.translated_value, '3.3.3.3')
                    self.assertEqual(rule.static_dst_nat.original_value, Host('nathost').href)
            elif rule.name == 'dstandsrcnat':
                self.assertEqual(rule.dynamic_src_nat.translated_ports, (1024, 65535))
                self.assertEqual(rule.dynamic_src_nat.translated_value, '5.5.5.5')
                self.assertEqual(rule.static_dst_nat.translated_value, '3.3.3.3')
            elif rule.name == 'nonatrule':
                self.assertFalse(rule.static_src_nat.has_nat)
                self.assertFalse(rule.dynamic_src_nat.has_nat)
                self.assertFalse(rule.static_dst_nat.has_nat)
                # Test unsed on attribute
                self.assertIsNone(rule.used_on)
                rule.used_on = Host('nonexistanthost') #Catch the ElementNotFound, no change
                self.assertIsNone(rule.used_on)
                rule.used_on = engine
                self.assertEqual(rule.used_on, 'natfw')
                
        # IPv6 NAT
        Host.create(name='myipv6', ipv6_address='2001:0db8:85a3:0000:0000:8a2e:0370:7334')
        policy.fw_ipv6_nat_rules.create(name='mynat', 
                                        sources=[Host('myipv6')], 
                                        destinations='any', 
                                        services='any', 
                                        dynamic_src_nat='2001:db8::2:1')
        
        rule_matches = policy.search_rule('nonatrule')
        self.assertIsInstance(rule_matches[0], IPv4NATRule)
        
        no_rule_match = policy.search_rule('blahblahfoo')
        self.assertTrue(len(no_rule_match) == 0)
        
        engine.delete()        
        policy.delete()
        Host('nathost').delete()
        Host('sourcenat').delete()
        Host('myipv6').delete()  
    
    def test_policy_upload(self):
        # This will just sit in the task queue because the engine will not be initialized, but still tests
        # that policy upload from policy itself triggers properly
        policy = FirewallPolicy.create(name='testpolicy', template='Firewall Inspection Template')
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
                self.assertIsNone(result)
        
        status = task_status(task)
        for _ in range(1, 5):
            if status.in_progress:
                print("Status still in progress: %s" % vars(status))
                self.assertIn(status.abort().code, [204, 400])
            else:
                print("Status no progress: %s" % vars(status))
                break
            
        engine.delete()
        # Try except required becuase SMC seems to have a timing issue where it will hold on
        # to a reference to the task even after it's aborted. When deleting the policy, the
        # SMC will complain that it has dependencies
        try:
            policy.delete()
        except DeleteElementFailed:
            pass
        
        
    def test_file_filtering_policy(self):
        # Not fully implemented
        policy = describe_file_filtering_policy()
        if policy:
            for rules in policy[0].file_filtering_rules.all():
                self.assertIsInstance(rules, FileFilteringRule)
          
        
if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
'''
Created on Feb 6, 2017

@author: davidlepage
'''
import unittest
from smc.policy.rule_elements import LogOptions, Action, AuthenticationOptions,\
    Service, Destination, Source
from smc.policy.rule_nat import DynamicSourceNAT, StaticSourceNAT, StaticDestNAT
from smc.elements.network import Host
from smc.base.model import Meta
from smc.api.exceptions import ElementNotFound
from mock.mock import PropertyMock, patch


class Test(unittest.TestCase):

    def setUp(self):
        pass
        #Create policy

    def tearDown(self):
        pass

    def test_log_options(self):
    
        options = LogOptions()
        options.log_accounting_info_mode = False
        options.log_level = 'stored'
        options.application_logging = 'enforced'
        options.user_logging = 'enforced'
        options.comment = 'my new comment!!'
        options.log_closing_mode = True
        options.log_level = 'transient'
        options.log_payload_additional = True
        options.log_payload_excerpt = True
        options.log_payload_record = True
        
        self.assertTrue(options.log_accounting_info_mode)
        self.assertTrue(options.log_closing_mode)
        self.assertEqual(options.log_level, 'transient')
        self.assertTrue(options.log_payload_additional)
        self.assertTrue(options.log_payload_excerpt)
        self.assertTrue(options.log_payload_record)
        self.assertEqual(options.user_logging, 'enforced')
        self.assertEqual(options.log_severity, -1)
        self.assertEqual(options.application_logging, 'enforced')
        
        o = options()
        for k, v in o.items():
            self.assertEqual(k, 'options')
            self.assertDictEqual(v, options.data)
        
    def test_authentication_options(self):
        
        options = AuthenticationOptions()
        self.assertFalse(options.methods)
        self.assertFalse(options.require_auth)
        self.assertEqual(options.timeout, 3600)
        self.assertFalse(options.users)
        
        o = options()
        for k, v in o.items():
            self.assertEqual(k, 'authentication_options')
            self.assertDictEqual(v, options.data)
            
    def test_action(self):
        
        action = Action(actions=['discard', 'refuse'])
        # Defaults
        self.assertEqual(action.action, 'allow')
        self.assertEqual(action.scan_detection, 'undefined')
        
        action.action = 'discard'
        self.assertEqual(action.action, 'discard')
        action.action = 'foo'
        self.assertEqual(action.action, 'discard')
        action.deep_inspection = True
        action.file_filtering = False
        action.dos_protection = True
        action.scan_detection = 'on'
        action.vpn = 'http://1.1.1.1'
        action.mobile_vpn = True
        
        self.assertTrue(action.deep_inspection)
        self.assertFalse(action.file_filtering)
        self.assertTrue(action.dos_protection)
        self.assertEqual(action.scan_detection, 'on')
        self.assertEqual(action.vpn, 'http://1.1.1.1')
        self.assertTrue(action.mobile_vpn)
        self.assertIsNone(action.user_response)
        
        self.assertFalse(action.connection_tracking_options.mss_enforced)
        self.assertEqual(action.connection_tracking_options.timeout, -1)
        mini, maxi = action.connection_tracking_options.mss_enforced_min_max
        self.assertEqual(mini, 0)
        self.assertEqual(maxi, 0)
        
        action.connection_tracking_options.state = 'normal'
        action.connection_tracking_options.timeout = 60
        action.connection_tracking_options.mss_enforced_min_max = (1400, 1450)
        action.connection_tracking_options.mss_enforced = True
        
        self.assertEqual(action.connection_tracking_options.state, 'normal')
        self.assertEqual(action.connection_tracking_options.timeout, 60)
        mini, maxi = action.connection_tracking_options.mss_enforced_min_max
        self.assertEqual(mini, 1400)
        self.assertEqual(maxi, 1450)
        self.assertTrue(action.connection_tracking_options.mss_enforced)
        
        o = action()
        for k, v in o.items():
            self.assertEqual(k, 'action')
            self.assertDictEqual(v, action.data)
        
        action = Action({'foo': 'bar'})
        self.assertDictEqual(action.data, {'foo': 'bar'})
        
    def test_services(self):

        service = Service(data={'any': True})
        source = Source()
        dest = Destination()
        self.assertEqual(service.data, {'any': True})
        self.assertEqual(source.data, {'none': True})
        self.assertEqual(dest.data, {'none': True})
        
        source.set_any()
        self.assertTrue(source.is_any)
        source.set_none()
        self.assertTrue(source.is_none)
        
        source.add('http://1.1.1.1')
        self.assertEqual(source.data, {'src': ['http://1.1.1.1']})
        source.set_none()
        source.add_many(['http://1.1.1.1', 'http://2.2.2.2'])
        self.assertEqual(source.data, {'src': ['http://1.1.1.1', 'http://2.2.2.2']})
        self.assertEqual(source.all_as_href(), ['http://1.1.1.1', 'http://2.2.2.2'])
        
        o = service()
        self.assertIsNotNone(o.get('services'))
        o = source()
        self.assertIsNotNone(o.get('sources'))
        o = dest()
        self.assertIsNotNone(o.get('destinations'))
    
    def test_dynamic_source_nat(self):
        
        options = LogOptions()
        
        rule_values = {}
        nat = DynamicSourceNAT(options.data)
        nat.translated_value = '12.12.12.12'
        nat.translated_ports = (2000, 60000)
        rule_values.update(options=nat.data)
        
        self.assertEqual(nat.translated_value, '12.12.12.12')
        self.assertEqual(nat.translated_ports, (2000, 60000))
        nat.translated_value = '13.13.13.13'
        nat.translated_ports = (1000, 10001)
        self.assertEqual(nat.translated_value, '13.13.13.13')
        self.assertEqual(nat.translated_ports, (1000, 10001))
        self.assertIsNone(nat.original_value)
        
        options = LogOptions()
        host = Host('test', meta=Meta(href='http://1.1.1.1'))
        nat = DynamicSourceNAT(options.data)
        nat.translated_ports = (6000, 10000)
        nat.translated_value = host
        self.assertEqual(nat.translated_ports, (6000, 10000))
        self.assertEqual(nat.translated_value, 'http://1.1.1.1')
        
        # Add bad host, translated value should not change
        with patch('smc.base.model.Element.href', new_callable=PropertyMock) as foo:
            foo.side_effect = ElementNotFound
            nat.translated_value = Host('foo')
            self.assertEqual(nat.translated_value, 'http://1.1.1.1') #Still original value
    
    def test_static_src_nat(self):
        options = LogOptions()
        nat = StaticSourceNAT(options.data)
        self.assertIsNone(nat.translated_value)
        self.assertIsNone(nat.original_value)
        
        # Original value as an element
        host = Host('test', meta=Meta(href='http://1.1.1.1'))
        nat.original_value = host
        self.assertEqual(nat.original_value, 'http://1.1.1.1') #as element href
        
        # Translated address as element href
        nat.translated_value = host
        self.assertEqual(nat.translated_value, 'http://1.1.1.1')
        # Specify IP for translated address
        nat.translated_value = '2.2.2.2'
        self.assertEqual(nat.translated_value, '2.2.2.2')
        
        #Incorrect format, needs to be href or element
        nat.original_value = '10.10.10.10' 
        self.assertEqual(nat.original_value, 'http://1.1.1.1') #same as original
        
        nat.original_value = 'http://2.2.2.2'
        self.assertEqual(nat.original_value, 'http://2.2.2.2')
        
        with patch('smc.base.model.Element.href', new_callable=PropertyMock) as foo:
            foo.side_effect = ElementNotFound
            self.assertEqual(nat.translated_value, '2.2.2.2') #Before
            nat.translated_value = Host('foo') #Invalid host
            self.assertEqual(nat.translated_value, '2.2.2.2') #After
            
            self.assertEqual(nat.original_value, 'http://2.2.2.2') #Before
            nat.original_value = Host('foo') #Invalid host
            self.assertEqual(nat.original_value, 'http://2.2.2.2') #After
    
    def test_static_dst_nat_add_original_value_then_translated(self):
        
        options = LogOptions()
        nat = StaticDestNAT(options.data)
    
        nat.original_value = 'http://1.1.1.1'
        self.assertEqual(nat.original_value, 'http://1.1.1.1')
        # Add translated value
        nat.translated_value = '2.2.2.2'
        self.assertEqual(nat.translated_value, '2.2.2.2')
    
        self.assertEqual(nat.translated_value, '2.2.2.2')
        self.assertEqual(nat.original_value, 'http://1.1.1.1')
        
        # Simulate SMC resolving translated value
        nat.data['static_dst_nat']['original_value'].update({'ip_descriptor': '1.1.1.1'})
        self.assertEqual(nat.original_value, '1.1.1.1')
        
    def test_static_dst_nat_add_translated_value_then_original(self):
        
        options = LogOptions()
        nat = StaticDestNAT(options.data)

        nat.translated_value = '2.2.2.2'
        self.assertEqual(nat.translated_value, '2.2.2.2')
            
        nat.original_value = 'http://1.1.1.1'
        self.assertEqual(nat.original_value, 'http://1.1.1.1')
        self.assertEqual(nat.translated_value, '2.2.2.2')
      
    def test_static_dst_nat_add_ports_first(self):
        options = LogOptions()
        nat = StaticDestNAT(options.data)
        self.assertIsNone(nat.translated_ports)
        nat.translated_ports = (6000, 7000)
        self.assertEquals(nat.translated_ports, (6000, 7000))
        nat.translated_value = 'http://1.1.1.1'
        self.assertEqual(nat.translated_ports, (6000, 7000))
        self.assertEqual(nat.translated_value, 'http://1.1.1.1')
    
    def test_static_dst_nat_add_translated_then_ports(self):
        options = LogOptions()
        nat = StaticDestNAT(options.data)
        nat.translated_value = '55.55.55.55'
        self.assertEqual(nat.translated_value, '55.55.55.55')
        nat.translated_ports = ('6005-6007', '8001-8002')
        self.assertEqual(nat.translated_value, '55.55.55.55')
        self.assertEqual(nat.translated_ports, ('6005-6007', '8001-8002'))   
    
    def test_automatic_proxy(self):
        options = LogOptions()
        nat = StaticDestNAT(options.data)
        self.assertIsNone(nat.automatic_proxy) #NAT is not yet configured
        nat.translated_value = '1.1.1.1'
        nat.automatic_proxy = True
        self.assertTrue(nat.automatic_proxy)
    
    def test_automatic_proxy_added_first(self):
        options = LogOptions()
        nat = StaticDestNAT(options.data)
        nat.automatic_proxy = True
        self.assertTrue(nat.automatic_proxy)

        
        
if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.test_log_options']
    unittest.main()
from functools import wraps
import unittest
import requests_mock
from smc.api.exceptions import LicenseError, NodeCommandFailed
from smc.core.node import Node, ApplianceStatus, NodeStatus, Diagnostic,\
    HardwareStatus, InterfaceStatus
from constants import url
from smc.base.model import Meta
from smc.base.util import save_to_file
from mocks import inject_mock_for_smc

def http304(func):
    """
    When cache is called, return 304 to indicate cache is current
    as it's statically set in the NodeTest classmethod
    """
    @wraps(func)
    def func_wrapper(*args, **kwargs):
        m = args[1]
        m.get('/node', status_code=304)
        func(*args, **kwargs)
    return func_wrapper
  
@requests_mock.Mocker()
class NodeTests(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        """ 
        Set up SMC Session object once per test class. Primary reason is
        to load the Mock session object as smc.api.session._session since
        this assumes we will not have a real connection.
        """
        super(NodeTests, cls).setUpClass()
        inject_mock_for_smc()
        cls.node = Node(meta=Meta(href='{}/node'.format(url)))
        etag, data = cls.node_cache()
        #cls.node._cache = Cache(cls.node, data, etag)
        cls.node.add_cache(data, etag)
    
    @classmethod
    def node_cache(self):
        return ('12345abcd', 
              {'activate_test': True,
               'disabled': False,
               'link': [{'href': '{}/fetch_license'.format(url),
                         'method': 'POST',
                         'rel': 'fetch'},
                        {'href': '{}/bind_license'.format(url),
                         'method': 'POST',
                         'rel': 'bind'},
                        {'href': '{}/unbind_license'.format(url),
                         'method': 'POST',
                         'rel': 'unbind'},
                        {'href': '{}/cancel_unbind_license'.format(url),
                         'method': 'POST',
                         'rel': 'cancel_unbind'},
                        {'href': '{}/initial_contact'.format(url),
                         'method': 'POST',
                         'rel': 'initial_contact'},
                        {'href': '{}/appliance_status'.format(url),
                         'method': 'GET',
                         'rel': 'appliance_status'},
                        {'href': '{}/status'.format(url),
                         'method': 'GET',
                         'rel': 'status'},
                        {'href': '{}/go_online'.format(url),
                         'method': 'PUT',
                         'rel': 'go_online'},
                        {'href': '{}/go_offline'.format(url),
                         'method': 'PUT',
                         'rel': 'go_offline'},
                        {'href': '{}/go_standby'.format(url),
                         'method': 'PUT',
                         'rel': 'go_standby'},
                        {'href': '{}/lock_online'.format(url),
                         'method': 'PUT',
                         'rel': 'lock_online'},
                        {'href': '{}/lock_offline'.format(url),
                         'method': 'PUT',
                         'rel': 'lock_offline'},
                        {'href': '{}/reset_user_db'.format(url),
                         'method': 'PUT',
                         'rel': 'reset_user_db'},
                        {'href': '{}/diagnostic'.format(url),
                         'method': 'GET',
                         'rel': 'diagnostic'},
                        {'href': '{}/send_diagnostic'.format(url),
                         'method': 'POST',
                         'rel': 'send_diagnostic'},
                        {'href': '{}/reboot'.format(url),
                         'method': 'PUT',
                         'rel': 'reboot'},
                        {'href': '{}/sginfo',
                         'method': 'GET',
                         'rel': 'sginfo'},
                        {'href': '{}/ssh'.format(url),
                         'method': 'PUT',
                         'rel': 'ssh'},
                        {'href': '{}/change_ssh_pwd'.format(url),
                         'method': 'PUT',
                         'rel': 'change_ssh_pwd'},
                        {'href': '{}/time_sync'.format(url),
                         'method': 'PUT',
                         'rel': 'time_sync'},
                        {'href': '{}/certificate_info'.format(url),
                         'method': 'GET',
                         'rel': 'certificate_info'},
                        {'href': '{}',
                         'method': 'GET',
                         'rel': 'self',
                         'type': 'firewall_node'}],
                'loopback_node_dedicated_interface': [],
                'name': 'thenode',
                'nodeid': 1})
    
    def del_cache_item(self, item):
        self.node.data['link'][:] = [d 
                                     for d in self.node.data['link'] 
                                     if d.get('rel') != item]
       
    def test_node_create(self, m):
        node = Node.create('mynode', 'virtual_fw_node')
        data = node.get('virtual_fw_node')
        self.assertEqual(data.get('name'), 'mynode node 1')
        self.assertEqual(data.get('nodeid'), 1)
    
    @http304
    def test_node_using_meta(self, m):
        node = Node(meta=Meta(href='{}/node'.format(url), type='virtual', name='mynode'))
        etag, data = NodeTests.node_cache()
        node.add_cache(data)
        self.assertEqual(node.name, 'mynode')
        self.assertEqual(node.type, 'virtual')
        self.assertEqual(node.nodeid, 1)
    
    @http304
    def test_fetch_license(self, m):
        m.post('/fetch_license', [{'status_code': 200},
                                  {'status_code': 400}])
        self.assertIsNone(self.node.fetch_license())
        self.assertRaises(LicenseError, lambda: self.node.fetch_license())
        
    @http304
    def test_bind_license(self, m):
        m.post('/bind_license', [{'status_code': 200},
                                 {'status_code': 400}])
        self.assertIsNone(self.node.bind_license())
        self.assertRaises(LicenseError, lambda: self.node.bind_license())
    
    @http304
    def test_unbind_license(self, m):
        m.post('/unbind_license', [{'status_code': 200},
                                   {'status_code': 400}])
        self.assertIsNone(self.node.unbind_license())
        self.assertRaises(LicenseError, lambda: self.node.unbind_license())
    
    @http304
    def test_cancel_unbind(self, m):
        m.post('/cancel_unbind_license', [{'status_code': 200},
                                          {'status_code': 400}])
        self.assertIsNone(self.node.cancel_unbind_license())
        self.assertRaises(LicenseError, lambda: self.node.cancel_unbind_license())
    
    @http304
    def test_go_online_offline_standby_lock(self, m):
        actions = ['go_online', 'go_offline', 'go_standby', 'lock_online',
                   'lock_offline']
        
        for action in actions:
            m.put('/{}'.format(action), [{'status_code': 200},
                                         {'status_code': 400}])

            self.assertIsNone(getattr(self.node, action)())
            self.assertRaises(NodeCommandFailed, lambda: getattr(self.node, action)())  

    @http304
    def test_status(self, m):
        
        status = {'dyn_up': '838', 'configuration_status': 'Installed', 
                  'version': 'version 6.1 #17028', 'name': 've-1 node 1', 
                  'status': 'Locked Online', 'state': 'READY', 
                  'installed_policy': 'Master Engine Policy', 
                  'platform': 'x86-64'}
        
        m.get('/status', [{'status_code': 200, 'json': status,
                           'headers': {'content-type': 'application/json'}},
                          {'status_code': 400}])
      
        node_dict = self.node.status()
        self.assertDictEqual(status, vars(node_dict))
        self.assertIsInstance(node_dict, NodeStatus)
        self.assertIsNone(node_dict.foo) #Attribute doesn't exist
        # Node failed
        self.assertRaises(NodeCommandFailed, lambda: self.node.status()) 
    
    @http304
    def test_reboot(self, m):
        m.put('/reboot', [{'status_code': 200},
                          {'status_code': 400}])
    
        self.assertIsNone(self.node.reboot())
        self.assertRaises(NodeCommandFailed, lambda: self.node.reboot())
    
    @http304
    def test_time_sync(self, m):
        m.put('/time_sync', [{'status_code': 200},
                             {'status_code': 400},
                             {'status_code': 200}])
        
        self.assertIsNone(self.node.time_sync())
        self.assertRaises(NodeCommandFailed, lambda: self.node.time_sync())
        # Some nodes do not have this attribute (i.e. virtual nodes)
        self.del_cache_item('time_sync')
        self.assertRaises(NodeCommandFailed, lambda: self.node.time_sync())
    
    @http304
    def test_reset_user_db(self, m):
        m.put('/reset_user_db', [{'status_code': 200},
                                 {'status_code': 400},
                                 {'status_code': 200}])
        
        self.assertIsNone(self.node.reset_user_db())
        self.assertRaises(NodeCommandFailed, lambda: self.node.reset_user_db())
        
        # Some nodes do not have this attribute (i.e. virtual nodes)
        self.del_cache_item('reset_user_db')
        self.assertRaises(NodeCommandFailed, lambda: self.node.reset_user_db())
    
    @http304
    def test_diagnostics(self, m):
        
        diag = {'diagnostics': [
                    {'diagnostic': {'name': 'SNMP Monitoring', 'enabled': False}}, 
                    {'diagnostic': {'name': 'User defined', 'enabled': False}}, 
                    {'diagnostic': {'name': 'Syslog', 'enabled': False}}]}
        
        m.get('/diagnostic', [{'status_code': 200, 'json': diag,
                               'headers': {'content-type': 'application/json'}},
                              {'status_code': 400},
                              {'status_code': 200}])
        
        d = self.node.diagnostic()
        self.assertIsInstance(d, list)
        for diag in d:
            self.assertIsInstance(diag, Diagnostic)
            
        # Check methods in diagnostics class
        diagnostic = d[0]
        self.assertEqual(diagnostic.name, 'SNMP Monitoring')
        self.assertTrue(diagnostic.state == False)
        diagnostic.enable()
        self.assertTrue(diagnostic.state == True)
        diagnostic.disable()
        self.assertTrue(diagnostic.state == False)
        # SMC returned a fail
        self.assertRaises(NodeCommandFailed, lambda: self.node.diagnostic())
        # Not supported on this node type
        self.del_cache_item('diagnostic')
        self.assertRaises(NodeCommandFailed, lambda: self.node.diagnostic())
    
    @http304
    def test_appliance_status(self, m):
        
        #status = {'interface_statuses': {'interface_status': [{'status': 'Up'}], 
        #          'hardware_statuses': {'hardware_statuses': [{'statuses': [], 'name': 'Database Version'}]}}}
        status = {'interface_statuses': {'interface_status': [{'flow_control': 'AutoNeg: off Rx: off Tx: off', 'capability': 'Normal Interface', 'mtu': 1500, 'aggregate_is_active': False, 'status': 'Up', 'name': 'eth0_0', 'port': 'Copper', 'speed_duplex': '1000 Mb/s / Full / Automatic', 'interface_id': 0}, {'flow_control': 'AutoNeg: off Rx: off Tx: off', 'capability': 'Normal Interface', 'mtu': 1500, 'aggregate_is_active': False, 'status': 'Up', 'name': 'eth0_1', 'port': 'Copper', 'speed_duplex': '1000 Mb/s / Full / Automatic', 'interface_id': 1}, {'flow_control': 'AutoNeg: off Rx: off Tx: off', 'capability': 'Normal Interface', 'mtu': 1500, 'aggregate_is_active': False, 'status': 'Up', 'name': 'eth0_2', 'port': 'Copper', 'speed_duplex': '1000 Mb/s / Full / Automatic', 'interface_id': 2}, {'flow_control': 'AutoNeg: off Rx: off Tx: off', 'capability': 'Normal Interface', 'mtu': 1500, 'aggregate_is_active': False, 'status': 'Down', 'name': 'eth0_3', 'port': 'Copper', 'speed_duplex': 'Half / Automatic', 'interface_id': 3}]}, 'hardware_statuses': {'hardware_statuses': [{'name': 'Anti-Malware', 'items': [{'name': 'Database Version', 'statuses': []}, {'name': 'Last Update', 'statuses': []}, {'name': 'Library Version', 'statuses': []}, {'name': 'Database Update Status', 'statuses': []}]}, {'name': 'File Systems', 'items': [{'name': 'Root', 'statuses': [{'value': '600 MB', 'status': -1, 'sub_system': 'File Systems', 'param': 'Partition Size', 'label': 'Root'}]}, {'name': 'Data', 'statuses': [{'value': '6.2%', 'status': -1, 'sub_system': 'File Systems', 'param': 'Usage', 'label': 'Data'}, {'value': '1937 MB', 'status': -1, 'sub_system': 'File Systems', 'param': 'Size', 'label': 'Data'}]}, {'name': 'Spool', 'statuses': [{'value': '4.5%', 'status': -1, 'sub_system': 'File Systems', 'param': 'Usage', 'label': 'Spool'}, {'value': '9729 MB', 'status': -1, 'sub_system': 'File Systems', 'param': 'Size', 'label': 'Spool'}]}, {'name': 'Tmp', 'statuses': [{'value': '0.0%', 'status': -1, 'sub_system': 'File Systems', 'param': 'Usage', 'label': 'Tmp'}, {'value': '3942 MB', 'status': -1, 'sub_system': 'File Systems', 'param': 'Size', 'label': 'Tmp'}]}, {'name': 'Swap', 'statuses': [{'value': '0.0%', 'status': -1, 'sub_system': 'File Systems', 'param': 'Usage', 'label': 'Swap'}, {'value': '1887 MB', 'status': -1, 'sub_system': 'File Systems', 'param': 'Size', 'label': 'Swap'}]}]}, {'name': 'GTI Cloud', 'items': [{'name': 'Connection', 'statuses': []}, {'name': 'Status', 'statuses': []}]}, {'name': 'MLC Connection', 'items': []}, {'name': 'Web Filtering', 'items': [{'name': 'Cloud Connection', 'statuses': []}]}]}}
        m.get('/appliance_status', [{'status_code': 200, 'json': status,
                                     'headers': {'content-type': 'application/json'}},
                                    {'status_code': 400}])
        
        result = self.node.appliance_status
        self.assertIsInstance(result, ApplianceStatus)
        for x in result.hardware_status:
            self.assertIsInstance(x, HardwareStatus)
            self.assertIsInstance(x.items, list)
            self.assertIsNotNone(x.name)
        for x in result.interface_status:
            self.assertIsInstance(x, InterfaceStatus)
            self.assertIsNotNone(x.name)
            if x.items.interface_id == 0:
                self.assertTrue(x.items.name == 'eth0_0')
            
        # Error returned from SMC
        self.assertRaises(NodeCommandFailed, lambda: self.node.appliance_status)
    
    @http304
    def test_ssh(self, m):
        m.put('/ssh', [{'status_code': 200},
                       {'status_code': 400},
                       {'status_code': 200}])
        self.assertIsNone(self.node.ssh())
        self.assertRaises(NodeCommandFailed, lambda: self.node.ssh())
        # Not supported on all nodes (virtual engines)
        self.del_cache_item('ssh')
        self.assertRaises(NodeCommandFailed, lambda: self.node.ssh())
    
    @http304
    def test_sginfo(self, m):
        pass
    
    @http304
    def test_change_ssh_pwd(self, m):
        m.put('/change_ssh_pwd', [{'status_code': 200},
                                  {'status_code': 400},
                                  {'status_code': 200}])
        
        self.assertIsNone(self.node.change_ssh_pwd('pwd'))
        self.assertDictEqual({'value': 'pwd'}, m.last_request.json())
        
        # Typically password requirements not met
        self.assertRaises(NodeCommandFailed, lambda: self.node.change_ssh_pwd('pwd'))
        self.del_cache_item('change_ssh_pwd')
        # Not supported
        self.assertRaises(NodeCommandFailed, lambda: self.node.change_ssh_pwd('pwd'))
    
    @http304
    def test_certificate_info(self, m):
    
        cert = {'revocation_date': 0, 
                'contactable_href': 'http://1.1.1.1', 
                'expiration_date': 0, 
                'serial_number': 0}
        
        m.get('/certificate_info', [{'status_code': 200, 'json': cert,
                                    'headers': {'content-type': 'application/json'}}])
        
        result = self.node.certificate_info()
        self.assertDictEqual(result, cert)                                                                                 
                                              
    @http304
    def test_initial_contact(self, m):
        m.post('/initial_contact', [{'status_code': 200, 'text': 'INITIAL_CONFIG',
                                     'headers': {'content-type': 'text/plain'}},
                                    {'status_code': 200, 'text': 'INITIAL_CONFIG',
                                     'headers': {'content-type': 'application/octet-stream'}},
                                    {'status_code': 200}])
        # As text content
        result = self.node.initial_contact()
        self.assertEqual(result, 'INITIAL_CONFIG')
        # As file
        self.assertRaises(NodeCommandFailed, lambda: self.node.initial_contact(filename='/foo'))
                         
        # Doesn't exist for certain engines (virtual)
        self.del_cache_item('initial_contact')
        self.assertRaises(NodeCommandFailed, lambda: self.node.initial_contact())
    
    @http304
    def test_diagnostic(self, m):
        m.post('/send_diagnostic', [{'status_code': 200},
                                    {'status_code': 400}])
        
        diag = Diagnostic({'enabled': True, 'name': 'SNMP Monitoring'})
        self.assertIsNone(self.node.send_diagnostic([diag]))
        self.assertRaises(NodeCommandFailed, lambda: self.node.send_diagnostic([]))
        
    # Node uses this util if saving initial contact to file
    def test_save_to_file(self, m):
        # Valid
        self.assertIsNone(save_to_file('blah', 'foo'))
        
    def test_save_to_bad_file(self, m):
        # Invalid file
        self.assertRaises(IOError, lambda: save_to_file('foo/efwef/', 'foo'))

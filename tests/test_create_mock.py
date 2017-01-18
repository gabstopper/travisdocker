import unittest
import requests
import requests_mock
import smc.actions
from smc import session as mysession
from smc.api.web import SMCAPIConnection
from smc.core.engines import Layer3Firewall, Layer2Firewall, IPS, MasterEngine,\
    FirewallCluster, MasterEngineCluster, Layer3VirtualEngine
from smc.core.engine import Engine
from smc.elements.helpers import location_helper, logical_intf_helper,\
    zone_helper
from .constants import url, register_request
from smc.api.exceptions import CreateEngineFailed
from pprint import pprint

    

def mock_create(m, func, args, uri=None, status_code=200):
    if status_code == 200: # Success create
        register_request(m, uri=uri, json={}, method='POST',
                         headers={'location': '{}/engine'.format(url),
                                  'content-type': 'application/json'})
    else:
        register_request(m, uri=uri, 
                         json={'message': 'engine fail'}, 
                         method='POST', status_code=status_code) 
    return func(**args)
            
@requests_mock.Mocker()
class CreateEngineTest(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        """ 
        Set up SMC Session object once per test class. Primary reason is
        to load the Mock session object as smc.api.session._session since
        this assumes we will not have a real connection.
        """
        super(CreateEngineTest, cls).setUpClass()
        adapter = requests_mock.Adapter()
        session = requests.Session()
        session.mount('mock', adapter)
        mysession._session = session
        mysession.cache.api_version = 6.1
        mysession._connection = SMCAPIConnection(mysession)
        cls.mock_entry_point()
    
    @classmethod
    def mock_entry_point(cls):
        """
        Entry points are used by create methods to either retrieve a resource,
        such as log server reference, locations, etc, or to POST data to the
        proper entry point. Populate session cache with needed links.
        """
        mysession._cache.api_entry = [{'rel': 'location', 
                                       'href': '{}/location'.format(url), 
                                       'method': 'GET'},
                                      {'rel': 'logical_interface',
                                       'href': '{}/logical_interface'.format(url),
                                       'method': 'GET'},
                                      {'rel': 'interface_zone',
                                       'href': '{}/interface_zone'.format(url),
                                       'method': 'GET'},
                                      {'rel': 'log_server',
                                       'href': '{}/log_server'.format(url),
                                       'method': 'GET'},
                                      {'rel': 'elements', 
                                       'href': '{}/elements'.format(url), 
                                       'method': 'GET'},
                                      {'rel': 'single_fw', 
                                       'href': '{}/single_fw'.format(url), 
                                       'method': 'GET'},
                                      {'rel': 'single_layer2',
                                       'href': '{}/single_layer2'.format(url),
                                       'method': 'GET'},
                                      {'rel': 'single_ips',
                                       'href': '{}/single_ips'.format(url),
                                       'method': 'GET'},
                                      {'rel': 'master_engine',
                                       'href': '{}/master_engine'.format(url),
                                       'method': 'GET'},
                                      {'rel': 'fw_cluster',
                                       'href': '{}/fw_cluster'.format(url),
                                       'method': 'GET'},
                                      {'rel': 'virtual_fw',
                                       'href': '{}/virtual_fw'.format(url),
                                       'method': 'GET'}]
            
    def mock_location_helper(self, m):
        """
        Mocks the real smc.elements.helpers.location_helper
        """
        register_request(m, 'elements?filter_context=location', 
                         json={'result': [{'href': '{}/location/1'.format(url),
                                           'name':'foolocation',
                                           'type':'location'}
                                          ]})
        return location_helper('foolocation')
    
    def mock_zone_helper(self, m):
        """
        Mocks the real smc.elements.helpers.zone_helper
        """
        register_request(m, 'elements?filter_context=interface_zone',
                         json={'result': [{'href': '{}/interface_zone/1'.format(url),
                                           'name':'interfacezone',
                                           'type':'interface_zone'}
                                          ]})
        return zone_helper('interfacezone')
    
    def mock_logical_intf_helper(self, m):
        """
        Mocks the real smc.elements.helpers.logical_intf_helper
        """
        register_request(m, 'elements?filter_context=logical_interface', 
                         json={'result': [{'href': '{}/logical_interface/1'.format(url),
                                           'name':'foointerface',
                                           'type':'logical_interface'}
                                          ]})
        return logical_intf_helper('foointerface')
    
    def mock_search_get_first_log_server(self, m):
        """
        If log_server_ref is ommitted from engine create constructor
        the smc.actions.get_first_log_server() method will be run within
        smc.core.engine.Engine.create to find the default log server href
        """
        register_request(m, 'log_server',
                         json={'result':[{'href':'{}/log_server/1'.format(url),
                                          'name':'LogServer 1.1.1.1',
                                          'type':'log_server'}]})
        return smc.actions.search.get_first_log_server()
    
    def mock_engine_virtual_resource_all(self, m, ve_name):
        """
        Mock call to MasterEngine.virtual_resource.all()
        :return: href of virtual resource based on name
        """
        register_request(m, 'virtual_resources',
                         json={'result':[{'href':'{}/virtual_resource/1'.format(url),
                                          'name':'{}'.format(ve_name),
                                          'type':'virtual_resource'}]})
        return '{}/virtual_resource/1'.format(url)
    
    def mock_master_engine_load(self, m, engine_name):
        """    
        Mock call to Engine('blah').load()
        Used when creating Layer3VirtualFirewall to find the master engine, and
        available virtual resource in the engine context.
        """
        # First call in load (SMC >=6.1) is to use a filter context against engines
        # Return as master_engine type
        register_request(m, 'elements?filter={}'.format(engine_name),
                         json={'result':[{'href':'{}/master_engine/1'.format(url),
                                          'name': engine_name,
                                          'type':'master_engine'}]})
        
        #m.get('/master_engine/1', [{'json': {'link': [{'href': '{}/virtual_resources'.format(url),
        #                                               'rel': 'virtual_resources',
        #                                               'type': 'virtual_resource'}]},
        #                            'headers': {'content-type': 'application/json'},
        #                            'status_code': 200
        #                            },
        #                           {'status_code': 304}
        #                          ])
        # Second request GETs the engine json; only provide what is necessary for
        # calling virtual_resource.all()                           
        register_request(m, 'master_engine/1',
                        json={'link':[{'href': '{}/virtual_resources'.format(url),
                                       'rel': 'virtual_resources',
                                       'type': 'virtual_resource'}]})
       
    def test_create_layer_3(self, m):
        
        location_ref = self.mock_location_helper(m)
        log_server_ref = self.mock_search_get_first_log_server(m)
        
        args = {'name':'myfw',
                'mgmt_ip': '1.1.1.1',
                'mgmt_network': '1.1.1.0/24',
                'enable_antivirus': True,
                'enable_gti': True,
                'default_nat': True,
                'location_ref': location_ref,
                'domain_server_address': ['8.8.8.8', '8.8.4.4']}
        
        engine_json = {
            'antivirus': {'antivirus_enabled': True,
                          'antivirus_update': 'daily',
                          'virus_log_level': 'stored',
                          'virus_mirror': 'update.nai.com/Products/CommonUpdater'},
            'default_nat': True,
            'domain_server_address': [{'rank': 0, 'value': '8.8.8.8'},
                                      {'rank': 0, 'value': '8.8.4.4'}],
            'gti_settings': {'file_reputation_context': 'gti_cloud_only'},
            'location_ref': location_ref,
            'log_server_ref': log_server_ref,
            'name': 'myfw',
            'nodes': [{'firewall_node': {'activate_test': True,
                                         'disabled': False,
                                         'loopback_node_dedicated_interface': [],
                                         'name': 'myfw node 1',
                                         'nodeid': 1}}],
            'physicalInterfaces': [{'physical_interface': {'interface_id': 0,
                                                           'interfaces': [{'single_node_interface': {'address': '1.1.1.1',
                                                                                                     'auth_request': True,
                                                                                                     'auth_request_source': False,
                                                                                                     'backup_heartbeat': False,
                                                                                                     'backup_mgt': False,
                                                                                                     'dynamic': False,
                                                                                                     'network_value': '1.1.1.0/24',
                                                                                                     'nicid': 0,
                                                                                                     'nodeid': 1,
                                                                                                     'outgoing': True,
                                                                                                     'primary_heartbeat': False,
                                                                                                     'primary_mgt': True,
                                                                                                     'reverse_connection': False}}],
                                                           'vlanInterfaces': [],
                                                           'zone_ref': None}}]}
        uri = 'single_fw'
        
        self.assertRaises(CreateEngineFailed, lambda: \
                          mock_create(m, Layer3Firewall.create, args, uri, 
                                      status_code=400))
       
        for hist in m.request_history:
            if hist.path_url.startswith('/single_fw'):
                post_data = hist.json()
        
        engine = mock_create(m, Layer3Firewall.create, args, uri)
        self.assertIsInstance(engine, Engine)
        self.assertEqual(engine.name, 'myfw')
        self.assertEqual(engine.type, uri)
        self.assertDictEqual(engine_json, post_data)
          
    def test_create_layer2(self, m):
        
        logical_if_ref = self.mock_logical_intf_helper(m)
        log_server_ref = self.mock_search_get_first_log_server(m)
        
        # Logical interface provided, here. During cretae process 
        # it will use a helper to find it by name or create it.
        args = {'name':'myfw',
                'mgmt_ip': '1.1.1.1',
                'mgmt_network': '1.1.1.0/24',
                'mgmt_interface': 0,
                'inline_interface': '1-2',
                'logical_interface': 'foointerface',
                'enable_antivirus': True,
                'enable_gti': True,
                'domain_server_address': ['8.8.8.8']}
    
        engine_json = {
            'antivirus': {'antivirus_enabled': True,
                          'antivirus_update': 'daily',
                          'virus_log_level': 'stored',
                          'virus_mirror': 'update.nai.com/Products/CommonUpdater'},
            'domain_server_address': [{'rank': 0, 'value': '8.8.8.8'}],
            'gti_settings': {'file_reputation_context': 'gti_cloud_only'},
            'log_server_ref': log_server_ref,
            'name': 'myfw',
            'nodes': [{'fwlayer2_node': {'activate_test': True,
                                         'disabled': False,
                                         'loopback_node_dedicated_interface': [],
                                         'name': 'myfw node 1',
                                         'nodeid': 1}}],
            'physicalInterfaces': [{'physical_interface': {'interface_id': 0,
                                                           'interfaces': [{'node_interface': {'address': '1.1.1.1',
                                                                                              'auth_request': False,
                                                                                              'backup_heartbeat': False,
                                                                                              'network_value': '1.1.1.0/24',
                                                                                              'nicid': 0,
                                                                                              'nodeid': 1,
                                                                                              'outgoing': True,
                                                                                              'primary_heartbeat': False,
                                                                                              'primary_mgt': True}}],
                                                           'vlanInterfaces': [],
                                                           'zone_ref': None}},
                                   {'physical_interface': {'interface_id': '1',
                                                           'interfaces': [{'inline_interface': {'failure_mode': 'normal',
                                                                                                'inspect_unspecified_vlans': True,
                                                                                                'logical_interface_ref': logical_if_ref,
                                                                                                'nicid': '1-2',
                                                                                                'zone_ref': None}}],
                                                           'vlanInterfaces': [],
                                                           'zone_ref': None}}]}
        uri = 'single_layer2'
       
        self.assertRaises(CreateEngineFailed, lambda: \
                          mock_create(m, Layer2Firewall.create, args, uri, 
                                      status_code=400))
        for hist in m.request_history:
            if hist.path_url.startswith('/single_layer2'):
                post_data = hist.json()
                      
        engine = mock_create(m, Layer2Firewall.create, args, uri)
        self.assertIsInstance(engine, Engine)
        self.assertEqual(engine.name, 'myfw')
        self.assertEqual(engine.type, uri)
        self.assertDictEqual(engine_json, post_data)
    
    def test_ips_create(self, m):
        
        logical_if_ref = self.mock_logical_intf_helper(m)
        log_server_ref = self.mock_search_get_first_log_server(m)
        
        args = {'name':'myfw',
                'mgmt_ip': '1.1.1.1',
                'mgmt_network': '1.1.1.0/24',
                'mgmt_interface': 0,
                'inline_interface': '1-2',
                'logical_interface': 'foointerface',
                'enable_antivirus': True,
                'enable_gti': True,
                'domain_server_address': ['8.8.8.8']}
    
        engine_json = {
            'antivirus': {'antivirus_enabled': True,
                          'antivirus_update': 'daily',
                          'virus_log_level': 'stored',
                          'virus_mirror': 'update.nai.com/Products/CommonUpdater'},
            'domain_server_address': [{'rank': 0, 'value': '8.8.8.8'}],
            'gti_settings': {'file_reputation_context': 'gti_cloud_only'},
            'log_server_ref': log_server_ref,
            'name': 'myfw',
            'nodes': [{'ips_node': {'activate_test': True,
                                    'disabled': False,
                                    'loopback_node_dedicated_interface': [],
                                    'name': 'myfw node 1',
                                    'nodeid': 1}}],
            'physicalInterfaces': [{'physical_interface': {'interface_id': 0,
                                                           'interfaces': [{'node_interface': {'address': '1.1.1.1',
                                                                                              'auth_request': False,
                                                                                              'backup_heartbeat': False,
                                                                                              'network_value': '1.1.1.0/24',
                                                                                              'nicid': 0,
                                                                                              'nodeid': 1,
                                                                                              'outgoing': True,
                                                                                              'primary_heartbeat': False,
                                                                                              'primary_mgt': True}}],
                                                           'vlanInterfaces': [],
                                                           'zone_ref': None}},
                                   {'physical_interface': {'interface_id': '1',
                                                           'interfaces': [{'inline_interface': {'failure_mode': 'normal',
                                                                                                'inspect_unspecified_vlans': True,
                                                                                                'logical_interface_ref': logical_if_ref,
                                                                                                'nicid': '1-2',
                                                                                                'zone_ref': None}}],
                                                           'vlanInterfaces': [],
                                                           'zone_ref': None}}]}
        uri = 'single_ips'
        
        self.assertRaises(CreateEngineFailed, lambda: \
                          mock_create(m, IPS.create, args, uri, 
                                      status_code=400))
        for hist in m.request_history:
            if hist.path_url.startswith('/single_ips'):
                post_data = hist.json()

        engine = mock_create(m, IPS.create, args, uri)
        self.assertIsInstance(engine, Engine)
        self.assertEqual(engine.name, 'myfw')
        self.assertEqual(engine.type, uri)
        self.assertDictEqual(engine_json, post_data)
      
    def test_master_engine_create(self, m):
        
        log_server_ref = self.mock_search_get_first_log_server(m)
        
        args = {'name':'myfw',
                'master_type': 'firewall',
                'mgmt_ip': '1.1.1.1',
                'mgmt_netmask': '1.1.1.0/24',
                'mgmt_interface': 0,
                'enable_antivirus': True,
                'enable_gti': True,
                'domain_server_address': ['8.8.8.8']}
        
        # Good engine json
        engine_json = {
            'antivirus': {'antivirus_enabled': True,
                          'antivirus_update': 'daily',
                          'virus_log_level': 'stored',
                          'virus_mirror': 'update.nai.com/Products/CommonUpdater'},
            'cluster_mode': 'standby',
            'domain_server_address': [{'rank': 0, 'value': '8.8.8.8'}],
            'gti_settings': {'file_reputation_context': 'gti_cloud_only'},
            'log_server_ref': log_server_ref,
            'master_type': 'firewall',
            'name': 'myfw',
            'nodes': [{'master_node': {'activate_test': True,
                                       'disabled': False,
                                       'loopback_node_dedicated_interface': [],
                                       'name': 'myfw node 1',
                                       'nodeid': 1}}],
            'physicalInterfaces': [{'physical_interface': {'interface_id': 0,
                                                           'interfaces': [{'node_interface': {'address': '1.1.1.1',
                                                                                              'auth_request': False,
                                                                                              'backup_heartbeat': False,
                                                                                              'network_value': '1.1.1.0/24',
                                                                                              'nicid': 0,
                                                                                              'nodeid': 1,
                                                                                              'outgoing': True,
                                                                                              'primary_heartbeat': True,
                                                                                              'primary_mgt': True}}],
                                                           'vlanInterfaces': [],
                                                           'zone_ref': None}}]}
        uri = 'master_engine'
        
        self.assertRaises(CreateEngineFailed, lambda: \
                          mock_create(m, MasterEngine.create, args, uri, 
                                      status_code=400))
        for hist in m.request_history:
            if hist.path_url.startswith('/master_engine'):
                post_data = hist.json()
                            
        engine = mock_create(m, MasterEngine.create, args, uri)
        self.assertIsInstance(engine, Engine)
        self.assertEqual(engine.name, 'myfw')
        self.assertEqual(engine.type, uri)
        self.assertDictEqual(engine_json, post_data)
    
    def test_create_firewall_cluster(self, m):
        
        log_server_ref = self.mock_search_get_first_log_server(m)
        # Specify zone_ref on create and verify the zone ref is resolved
        zone_ref = self.mock_zone_helper(m)
        
        args = {'name': 'myfw',
                'cluster_virtual': '1.1.1.1',
                'cluster_mask': '1.1.1.0/24',
                'cluster_nic': 0,
                'macaddress': '02:02:02:02:02:02',
                'nodes': [{'address': '1.1.1.2', 'network_value': '1.1.1.0/24', 'nodeid':1},
                          {'address': '1.1.1.3', 'network_value': '1.1.1.0/24', 'nodeid':2}],
                'domain_server_address': ['8.8.8.8'], 
                'zone_ref': zone_ref}
        
        engine_json = {
            'domain_server_address': [{'rank': 0, 'value': '8.8.8.8'}],
            'log_server_ref': log_server_ref,
            'name': 'myfw',
            'nodes': [{'firewall_node': {'activate_test': True,
                                         'disabled': False,
                                         'loopback_node_dedicated_interface': [],
                                         'name': 'myfw node 1',
                                         'nodeid': 1}},
                      {'firewall_node': {'activate_test': True,
                                         'disabled': False,
                                         'loopback_node_dedicated_interface': [],
                                         'name': 'myfw node 2',
                                         'nodeid': 2}}],
                       'physicalInterfaces': [{'physical_interface': {'cvi_mode': 'packetdispatch',
                                                                      'interface_id': 0,
                                                                      'interfaces': [{'cluster_virtual_interface': {'address': '1.1.1.1',
                                                                                                                    'auth_request': True,
                                                                                                                    'network_value': '1.1.1.0/24',
                                                                                                                    'nicid': 0}},
                                                                                     {'node_interface': {'address': '1.1.1.2',
                                                                                                         'auth_request': False,
                                                                                                         'backup_heartbeat': False,
                                                                                                         'network_value': '1.1.1.0/24',
                                                                                                         'nicid': 0,
                                                                                                         'nodeid': 1,
                                                                                                         'outgoing': True,
                                                                                                         'primary_heartbeat': True,
                                                                                                         'primary_mgt': True}},
                                                                                     {'node_interface': {'address': '1.1.1.3',
                                                                                                         'auth_request': False,
                                                                                                         'backup_heartbeat': False,
                                                                                                         'network_value': '1.1.1.0/24',
                                                                                                         'nicid': 0,
                                                                                                         'nodeid': 2,
                                                                                                         'outgoing': True,
                                                                                                         'primary_heartbeat': True,
                                                                                                         'primary_mgt': True}}],
                                                                        'macaddress': '02:02:02:02:02:02',
                                                                        'vlanInterfaces': [],
                                                                        'zone_ref': zone_ref}}]}
        uri = 'fw_cluster'
        
        self.assertRaises(CreateEngineFailed, lambda: \
                          mock_create(m, FirewallCluster.create, args, uri, 
                                      status_code=400))
        for hist in m.request_history:
            if hist.path_url.startswith('/fw_cluster'):
                post_data = hist.json()
        
        engine = mock_create(m, FirewallCluster.create, args, uri)
        self.assertIsInstance(engine, Engine)
        self.assertEqual(engine.name, 'myfw')
        self.assertEqual(engine.type, uri)
        self.assertDictEqual(engine_json, post_data)
    
    def test_master_engine_cluster(self, m):
    
        log_server_ref = self.mock_search_get_first_log_server(m)
        
        args = {'name': 'myfw',
                'master_type': 'firewall', 
                'macaddress': '22:22:22:22:22:22', 
                'nodes': [{'address':'5.5.5.2', 
                            'network_value':'5.5.5.0/24', 
                            'nodeid':1},
                          {'address':'5.5.5.3', 
                           'network_value':'5.5.5.0/24', 
                           'nodeid':2}]
                }
        
        engine_json = {
            'cluster_mode': 'standby',
            'domain_server_address': [],
            'log_server_ref': log_server_ref,
            'master_type': 'firewall',
            'name': 'myfw',
            'nodes': [{'master_node': {'activate_test': True,
                                       'disabled': False,
                                       'loopback_node_dedicated_interface': [],
                                       'name': 'myfw node 1',
                                       'nodeid': 1}},
                      {'master_node': {'activate_test': True,
                                       'disabled': False,
                                       'loopback_node_dedicated_interface': [],
                                       'name': 'myfw node 2',
                                       'nodeid': 2}}],
            'physicalInterfaces': [{'physical_interface': {'interface_id': 0,
                                                           'interfaces': [{'node_interface': {'address': '5.5.5.2',
                                                                                              'auth_request': False,
                                                                                              'backup_heartbeat': False,
                                                                                              'network_value': '5.5.5.0/24',
                                                                                              'nicid': 0,
                                                                                              'nodeid': 1,
                                                                                              'outgoing': True,
                                                                                              'primary_heartbeat': True,
                                                                                              'primary_mgt': True}},
                                                                          {'node_interface': {'address': '5.5.5.3',
                                                                                              'auth_request': False,
                                                                                              'backup_heartbeat': False,
                                                                                              'network_value': '5.5.5.0/24',
                                                                                              'nicid': 0,
                                                                                              'nodeid': 2,
                                                                                              'outgoing': True,
                                                                                              'primary_heartbeat': True,
                                                                                              'primary_mgt': True}}],
                                                           'macaddress': '22:22:22:22:22:22',
                                                           'vlanInterfaces': [],
                                                           'zone_ref': None}}]}
                               
        uri = 'master_engine'
        
        self.assertRaises(CreateEngineFailed, lambda: \
                          mock_create(m, MasterEngineCluster.create, args, uri, 
                                      status_code=400))
        for hist in m.request_history:
            if hist.path_url.startswith('/master_engine'):
                post_data = hist.json()
       
        engine = mock_create(m, MasterEngineCluster.create, args, uri)
        self.assertIsInstance(engine, Engine)
        self.assertEqual(engine.name, 'myfw')
        self.assertEqual(engine.type, uri)
        self.assertDictEqual(engine_json, post_data)
    
    def test_virtual_firewall_create(self, m):
        """
        Virtual FW instances require that a MasterEngine and VirtualResource 
        has already been created on the Master Engine: 
        MasterEngine.virtual_resource.create(.....).
        """
        # Set up mocks for engine loading and virtual resource call
        self.mock_master_engine_load(m, 'mymasterengine')
        virtual_ref = self.mock_engine_virtual_resource_all(m, 'myvirtual')
        
        #engine = Engine('mymasterengine').load()
        #for x in engine.virtual_resource.all():
        #    print(vars(x))
        
        args = {'name': 'myfw', 
                'master_engine': 'mymasterengine', 
                'virtual_resource':'myvirtual', 
                'interfaces': [{'interface_id': 0,
                                'address': '1.1.1.1',
                                'network_value': '1.1.1.0/24'}], 
                'default_nat': False, 
                'outgoing_intf': 0,
                'domain_server_address': ['8.8.8.8']}
        
        engine_json = {
            'domain_server_address': [{'rank': 0, 'value': '8.8.8.8'}],
            'name': 'myfw',
            'nodes': [{'virtual_fw_node': {'activate_test': True,
                                           'disabled': False,
                                           'loopback_node_dedicated_interface': [],
                                           'name': 'myfw node 1',
                                           'nodeid': 1}}],
            'physicalInterfaces': [{'virtual_physical_interface': {'interface_id': 0,
                                                                   'interfaces': [{'single_node_interface': {'address': '1.1.1.1',
                                                                                                             'auth_request': True,
                                                                                                             'auth_request_source': False,
                                                                                                             'backup_heartbeat': False,
                                                                                                             'backup_mgt': False,
                                                                                                             'dynamic': False,
                                                                                                             'network_value': '1.1.1.0/24',
                                                                                                             'nicid': 0,
                                                                                                             'nodeid': 1,
                                                                                                             'outgoing': True,
                                                                                                             'primary_heartbeat': False,
                                                                                                             'primary_mgt': False}}],
                                                                   'vlanInterfaces': [],
                                                                   'zone_ref': None}}],
            'virtual_resource': virtual_ref}
        
        uri = 'virtual_fw'
        
        self.assertRaises(CreateEngineFailed, lambda: \
                          mock_create(m, Layer3VirtualEngine.create, args, uri, 
                                      status_code=400))
        # Get data already sent in initial POST. It would have succeeded but status
        # code trigger a fail.
        for hist in m.request_history:
            if hist.path_url.startswith('/virtual_fw'):
                post_data = hist.json()
        
        engine = mock_create(m, Layer3VirtualEngine.create, args, uri)
        self.assertIsInstance(engine, Engine)
        self.assertEqual(engine.name, 'myfw')
        self.assertEqual(engine.type, uri)
        self.assertDictEqual(engine_json, post_data)
        
        # Fail if virtual engine within master engine is not found
        args['virtual_resource'] = 'foo'
        self.assertRaises(CreateEngineFailed, lambda: \
                          mock_create(m, Layer3VirtualEngine.create, args, uri))
        
    
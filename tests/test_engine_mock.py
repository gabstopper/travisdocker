import unittest
from smc import session as mysession
import requests_mock
from constants import url, api_key, register_request, register_get_and_reply
from smc.core.engine import Engine, VirtualResource, InternalGateway,\
    InternalEndpoint
from smc.core.interfaces import Interface, PhysicalInterface
from smc.base.model import Meta
from smc.api.exceptions import UnsupportedEngineFeature,\
    UnsupportedInterfaceType, SMCConnectionError, EngineCommandFailed,\
    TaskRunFailed, LoadEngineFailed, CertificateError
from smc.core.resource import RouteTable, Route, Routing, RoutingNode, Alias, Snapshot
from smc.core.node import Node
from smc.vpn.elements import VPNSite
from smc.api.web import SMCResult

def raise_within(request, context):
    raise SMCConnectionError
   
@requests_mock.Mocker()
class EngineMocks(unittest.TestCase):
    
    def setUp(self):
        mysession.login(url, api_key)
        
    def tearDown(self):
        mysession.logout()
    
    def test_engine_rename(self, m):
        engine = Engine(name='test', meta=Meta(name='test', type='single_fw', href='{}/engine'.format(url)))
        
        engine._cache = ('etag', {'name': 'test',
                                  'nodes': [{'firewall_node': {'activate_test': True,
                                                                 'engine_version': 'version 6.1 #17028',
                                                                 'name': 'test node 1',
                                                                 'nodeid': 1}}],
                                  'link': [{'href': '{}/internal_gateway'.format(url),
                                            'rel': 'internal_gateway'},
                                           {'href': '{}/nodes'.format(url),
                                            'rel': 'nodes'}]})
        # Make smc-python pull from engine cache json
        register_request(m, 'engine', status_code=304)
        register_request(m, 'engine', json={}, method='PUT')
        # Internal gateway interception
        register_request(m, 'internal_gateway', 
                         json=[{'name': 'test - Primary', 
                                'href': '{}/internal_gateway/5354'.format(url), 
                                'type': 'internal_gateway'}])
        
        register_request(m, 'nodes', 
                         json=[{'href':'{}/mynode'.format(url), 'type':'single_fw', 'name':'test node 1'}])
       
        # Set internal gateway cache 
        engine.internal_gateway._cache = ('etag', {'name': 'test Primary'})
        # Get internal gateway from cache
        register_request(m, 'internal_gateway/5354', status_code=304)
        # Return empty json for success on modify_attribute call
        register_request(m, 'internal_gateway/5354', status_code=200, json={}, method='PUT')
        # When engine.nodes called, return node json
        register_request(m, 'mynode', status_code=200, json={'nodeid':1, 'name':'test'}, method='GET')
        
        engine.rename('bar')
        self.assertTrue(engine.name, 'bar')
        
    def test_engine_create(self, m):
        
        # Log Server GET when log_server_ref is not provided
        register_request(m, '{}/elements/log_server'.format(mysession.api_version), 
                         json=[{'href': url}])
        
        # OSPF Default Profile GET when profile not specified, returns META
        register_request(m, '{}/elements/ospfv2_profile'.format(mysession.api_version),
                         json=[{'name': 'Default OSPFv2 Profile', 
                                'href': '{}/ospf'.format(url), 
                                'type': 'ospfv2_profile'}])
        # After META, follow on request gets full json to check attributes
        register_request(m, 'ospf', 
                         json={'system': True,
                               'href': url})
    
        engine = Engine.create(name='foo', 
                               node_type='virtual_fw_node', 
                               physical_interfaces=[{'virtual_physical_interface': {'aggregate_mode': 'none'}}],
                               nodes=2, 
                               domain_server_address=['1.1.1.1', '2.2.2.2'], 
                               enable_antivirus=True, 
                               enable_gti=True, 
                               default_nat=True, 
                               location_ref=url,
                               enable_ospf=True)
        self.assertEqual(engine['antivirus']['antivirus_enabled'], True)
        self.assertEqual(engine['default_nat'], True)
        self.assertEqual(engine['name'], 'foo')
        self.assertTrue(len(engine['nodes']) == 2)
        for node in engine['nodes']:
            for nodetype, _ in node.items():
                self.assertEqual(nodetype, 'virtual_fw_node')
        self.assertEqual(engine['log_server_ref'], url)
        self.assertEqual(engine['location_ref'], url)
        for dns in engine['domain_server_address']:
            self.assertIn(dns.get('value'), ['1.1.1.1', '2.2.2.2'])
        self.assertTrue(engine['dynamic_routing']['ospfv2'].get('enabled'))
        self.assertTrue(engine['dynamic_routing']['ospfv2'].get('ospfv2_profile_ref').startswith(url))

    def test_permissions_pass(self, m):
        uri = 'permissions'
    
        register_get_and_reply(m, uri, 
                               reply_status=200, 
                               reply_json={'granted_access_control_list': [], 
                                           'cluster_ref': url}, 
                               reply_method='GET')
        engine = Engine(name='foo', meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertIsInstance(engine.permissions(), dict)
    
    def test_permissions_fail(self, m):
        uri = 'permissions'
        
        register_get_and_reply(m, uri, 
                               reply_status=200, 
                               reply_json={}, 
                               reply_method='GET')
        engine = Engine(name='foo', meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertRaises(UnsupportedEngineFeature, lambda: engine.permissions())    
    
    def test_blacklist_pass(self, m):
        uri = 'blacklist'
        
        register_get_and_reply(m, uri, 
                               reply_status=201, 
                               reply_method='POST')
        engine = Engine(name='foo', meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertIsNone(engine.blacklist('1.1.1.2/32', '2.3.4.5/32'))
        
    def test_blacklist_fail(self, m):
        uri = 'blacklist'
        
        register_get_and_reply(m, uri, 
                               reply_status=400, 
                               reply_json={"details":["Illegal object type"]}, 
                               reply_method='POST')
        engine = Engine(name='foo', meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertRaises(EngineCommandFailed, lambda: engine.blacklist('0.0.1.0', '2.3.4.5'))
        
    def test_blacklist_flush_pass(self, m):
        uri = 'flush_blacklist'
        register_get_and_reply(m, uri, 
                               reply_status=204,
                               reply_method='DELETE')
        engine = Engine(name='foo', meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertIsNone(engine.blacklist_flush())
        
    def test_blacklist_flush_fail(self, m):
        uri = 'flush_blacklist'
        
        register_get_and_reply(m, uri, 
                               reply_status=500, 
                               reply_json={'details':'Impossible to flush all blacklist entries'}, 
                               reply_method='DELETE')
        engine = Engine(name='foo', meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertRaises(EngineCommandFailed, lambda: engine.blacklist_flush())
       
    def test_add_route_pass(self, m):
        uri = 'add_route'
        register_get_and_reply(m, uri, 
                               reply_status=200, 
                               reply_method='POST')
        engine = Engine(name='foo', meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertIsNone(engine.add_route('1.1.1.1', '1.2.3.4'))
        
    def test_add_route_fail(self, m):
        uri = 'add_route'
        
        register_get_and_reply(m, uri, 
                               reply_status=500, 
                               reply_json={"details":["No route can be added"]},
                               reply_method='POST')
        engine = Engine(name='foo', meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertRaises(EngineCommandFailed, lambda: engine.add_route('1.1.1.1', '1.2.3.4'))

    def test_antispoofing(self, m):
        uri = 'antispoofing'
        register_get_and_reply(m, uri, 
                               reply_status=200, 
                               reply_json={'test': 'foo'}, 
                               reply_method='GET')
        
        engine = Engine(name='foo', meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertIsInstance(engine.antispoofing(), dict)
                 
    def test_virtual_resource_pass(self, m):
        uri = 'virtual_resources'
        
        virtual_res = [{'name': 've-2', 
                        'href': url, 
                        'type': 'virtual_resource'},
                       {'name': 've-3', 
                        'href': url, 
                        'type': 'virtual_resource'}]
        
        register_get_and_reply(m, uri, 
                               reply_status=200,
                               reply_method='GET',
                               reply_json=virtual_res)
        engine = Engine(name='foo', meta=Meta(href='{}/{}'.format(url, uri)))
        virtual_res_names = [res.get('name') for res in virtual_res]
        for virtual in engine.virtual_resource.all():
            self.assertIsInstance(virtual, VirtualResource)
            self.assertIn(virtual.name, virtual_res_names)

    def test_virtual_resource_fail(self, m):
        uri = 'virtual_resources'
        register_request(m, uri, 
                         status_code=200, 
                         json={'link':[
                                        {
                                         'href': '{}/{}'.format(url, uri),
                                         'method': 'POST',
                                         'rel': 'foo'
                                        }
                                      ]
                              })
        
        engine = Engine(name='foo', meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertRaises(UnsupportedEngineFeature, lambda: engine.virtual_resource)
    
    def test_interface_pass(self, m):
        uri = 'interfaces'
         
        interfaces = [{'type':'physical_interface', 
                       'href': url, 
                       'name':'Interface 0'},
                      {'type': 'test',
                       'href': url,
                       'name': 'foo'}]
        
        register_get_and_reply(m, uri, 
                               reply_status=200,
                               reply_method='GET',
                               reply_json=interfaces)
        
        engine = Engine(name='foo', meta=Meta(href='{}/{}'.format(url, uri)))
        for intf in engine.interface.all():
            if intf.name == 'Interface 0':
                self.assertIsInstance(intf, PhysicalInterface)
            else:
                self.assertEqual(intf.name, 'foo')
                self.assertIsInstance(intf, Interface)
    
    def test_interfaces_pass(self, m):
        intf = ['tunnel_interface',
                'physical_interface', 
                'virtual_physical_interface']
        
        for interface in intf:
            interfaces = [{'name': 'Interface 1', 
                           'href': url, 
                           'type': interface},
                          {'name': 'Interface 2',
                           'href': url,
                           'type': interface}]
            
            register_get_and_reply(m, uri=interface, 
                                   reply_status=200, 
                                   reply_json=interfaces, 
                                   reply_method='GET')
            
            engine = Engine(name='foo', meta=Meta(href='{}/{}'.format(url, interface)))
            names = [name.get('name') for name in interfaces]
            pointer = getattr(engine, interface).all()
            for intf in pointer:
                # Each class should have 'typeof' attribute
                self.assertEqual(type(intf).typeof, interface)
                self.assertIn(intf.name, names)
    
    def test_interfaces_fail(self, m):
        intf = ['tunnel_interface',
                'physical_interface', 
                'virtual_physical_interface',
                'switch_physical_interface',
                'wireless_interface',
                'adsl_interface',
                'modem_interface']
        
        for interface in intf:
            register_request(m, interface, 
                             status_code=200, 
                             json={'link':[
                                           {
                                            'href': '{}/{}'.format(url, interface),
                                            'method': 'POST',
                                            'rel': 'foo'
                                            }
                                           ]
                                   })
            engine = Engine(name='foo', meta=Meta(href='{}/{}'.format(url, interface)))
            print(interface)
            self.assertRaises(UnsupportedInterfaceType, lambda: getattr(engine, interface))

    def test_unimplemented_interfaces(self, m):
        # Unimplemented interfaces are ones not conforming to interface types defined in
        # test_interfaces_pass. All interfaces will have a similar structure but some very
        # uncommonly used interfaces may not have been implemented and will return generic
        # json data back instead.
        intf = ['modem_interface', 'adsl_interface', 'wireless_interface',
                'switch_physical_interface']
        for interface in intf:
            register_get_and_reply(m, interface,
                                   reply_json=[],
                                   reply_method='GET')
            engine = Engine(name='foo', meta=Meta(href='{}/{}'.format(url, interface)))
            self.assertIsInstance(getattr(engine, interface), list)
           
    def test_refresh_and_upload_fail(self, m):
        #uri = 'refresh'
        uris = ['refresh', 'upload']
        for uri in uris:
            register_get_and_reply(m, uri,
                                   reply_status=400,  
                                   reply_json={'details': '{} failed'.format(uri)}, 
                                   reply_method='POST')
            engine = Engine(name='foo', meta=Meta(href='{}/{}'.format(url, uri)))
            self.assertRaises(TaskRunFailed, lambda: getattr(engine, uri)())
      
    def test_refresh_and_upload_pass(self, m): 
        uris = ['refresh','upload']
    
        task = {'last_message': '', 
                'waiting_inputs': False, 
                'link': [{'href': url, 
                          'method': 'GET', 
                          'rel': 'self', 
                          'type': 'task_progress'}, 
                         {'href': url, 
                          'method': 'DELETE', 
                          'rel': 'abort'}], 
                'resource': [], 
                'follower': '{}/follower'.format(url)}
            
        for uri in uris:
            register_get_and_reply(m, uri, 
                                   reply_status=200, 
                                   reply_json=task, 
                                   reply_method='POST')
            engine = Engine(name='foo', meta=Meta(href='{}/{}'.format(url, uri)))
            follower = getattr(engine, uri)(wait_for_finish=False)
            # Test generator and make sure it matches our follower link sent in
            self.assertEqual(next(follower), task.get('follower'))

    def test_generate_snapshot_pass_and_fail(self, m):
        uri = 'generate_snapshot'
        
        register_get_and_reply(m, uri, 
                               reply_status=200, 
                               reply_text='snapshot_content', 
                               reply_method='GET',
                               reply_headers={'content-type': 'application/zip'})
        
        engine = Engine(name='foo', meta=Meta(href='{}/{}'.format(url, uri)))
        # Fail, would raise IOError on web tier due to invalid directory
        self.assertRaises(EngineCommandFailed, lambda: engine.generate_snapshot(filename='/'))
        # Success, results stored in smcresult.content attribute
        result = engine.generate_snapshot('blah.txt').content
        self.assertEqual(result.rsplit('/', 1)[-1], 'blah.txt')
    
    def test_snapshot_pass(self, m):
        uri = 'snapshots'
        
        result = [{'href': '{}/snapshot_class'.format(url),
                   'name':'Master Engine Policy (2017-01-14 07:57:08)',
                   'type':'snapshot'}]
        snapshot = [{'name': 'Master Engine Policy (2017-01-14 07:57:08)', 
                     'type': 'snapshot', 
                     'href': url}]
        
        register_get_and_reply(m, uri, 
                               reply_status=200, 
                               reply_json=result, 
                               reply_method='GET')
        # Return the snapshot as class
        register_request(m, '{}/snapshot_class', 
                         status_code=200, 
                         json=snapshot)
        
        engine = Engine(name='foo', meta=Meta(href='{}/{}'.format(url, uri)))
        snapshot_data = engine.snapshots()
        self.assertIsInstance(snapshot_data, list)
        self.assertIsInstance(snapshot_data[0], Snapshot)
        self.assertEqual(snapshot_data[0].name, snapshot[0].get('name'))
    
    def test_snapshot_download_pass_and_fail(self, m):
        uri = 'snapshot'
        
        snapshot_j = {'name': 'Master Engine Policy (2017-01-14 07:57:08)', 
                      'type': 'snapshot', 
                      'href': '{}/{}'.format(url, uri)}
        
        snapshot = Snapshot(meta=Meta(**snapshot_j))
        self.assertEqual(snapshot.name, snapshot_j.get('name'))
        
        register_request(m, uri, 
                         status_code=200, 
                         json={'link':[{
                                        'href': '{}/content'.format(url),
                                        'method': 'POST',
                                        'rel': 'content'
                                        }]
                                }, 
                         )
    
        full_snapshot = {'upload_time': '2017-01-14T13:57:08Z', 
                         'link': [{'href': url, 
                                   'rel': 'content', 
                                   'method': 'GET'}, 
                                  {'type': 'snapshot', 
                                   'href': url, 
                                   'rel': 'self', 
                                   'method': 'GET'}], 
                         'package_id': 838, 
                         'target': url, 
                         'policy_ref': url, 
                         'name': 'Master Engine Policy', 
                         'uploader': 'dev'}
        
        register_request(m, 'content', 
                         status_code=200, 
                         json=full_snapshot)
        
        self.assertRaises(EngineCommandFailed, lambda: snapshot.download(filename='/'))
        smcresult = snapshot.download()
        # Without filename specific, default save to local directory, use snapshot.name.zip
        self.assertEqual(smcresult.content.rsplit('/', 1)[-1], '{}.zip'.format(snapshot.name))
    
    def test_load_engine_with_pre61(self, m):
        # This will follow the same branch for smc version >=6.1 also
        orig_version = mysession.api_version
        
        # Force API version to <6.1
        mysession._cache.api_version = 6.0
        self.assertTrue(mysession._cache.api_version < 6.1)
        
        engine = Engine('foo') # Reference engine we want
        
        valid_engine = {'name': 'foo', 
                        'href': '{}/foo'.format(url), 
                        'type': 'virtual_fw'}
        # Initial meta href returned from search.element_info_as_json
        engine_j = []
    
        # Get past initial generic search by name; uses search.element_info_as_json
        register_request(m, '{}/elements?filter=foo&exact_match=True'.format(orig_version), 
                         json=engine_j)
        
        # Return engine json structure
        engine_load_no_nodes = {'engine_version': 'version 6.1 #17028',
                                'name': 'foo',
                                'nat_definition': [],
                                'nodes': [],
                                'link': [{'href': '{}/nodes'.format(url),
                                          'rel': 'nodes'}]}
    
        # Once above json is returned, follow on query comes to URL specified in href
        register_request(m, 'foo', 
                         status_code=200, 
                         json=engine_load_no_nodes)
        # No nodes, simulates no results on SMC <6.1
        self.assertRaises(LoadEngineFailed, lambda: engine.load())
        engine_j.append(valid_engine) # Simulates non-engine type (no 'nodes' dict)
        self.assertRaises(LoadEngineFailed, lambda: engine.load())
        
        # Onto valid
        # Add valid node json to engine level
        engine_load_no_nodes.get('nodes').append({'virtual_fw_node': {'activate_test': True}})
        engine = engine.load()
        self.assertIsInstance(engine, Engine)
        self.assertEqual(engine.version, engine_load_no_nodes.get('engine_version'))
        self.assertEqual(engine.type, engine_j[0].get('type'))
        
        # Set node query, simulates called def nodes()
        register_request(m, 'nodes', 
                         json=engine_j)
        node = engine.nodes
        self.assertIsInstance(node, list)
        self.assertIsInstance(node[0], Node) 
    

@requests_mock.Mocker()
class InternalGatewayMocks(unittest.TestCase):
    
    def setUp(self):
        mysession.login(url, api_key)
        
    def tearDown(self):
        mysession.logout()
    
    def meta(self, uri):
        internal_gw = {'type': 'internal_gateway', 
                       'name': 'testfw - Primary', 
                       'href': '{}/{}'.format(url, uri)}
        
        gateway = InternalGateway(meta=Meta(**internal_gw))
        self.assertIsInstance(gateway, InternalGateway)
        return gateway
    
    def cache(self):
        return ('etag', {'antivirus': False,
                         'gateway_profile': 'http://172.18.1.150:8082/6.1/elements/gateway_profile/31',
                         'link': [{'href': '{}/generate_certificate_ref'.format(url),
                                   'method': 'POST',
                                   'rel': 'generate_certificate'},
                                  {'href': '{}/vpn_site'.format(url),
                                   'method': 'GET',
                                   'rel': 'vpn_site',
                                   'type': 'vpn_site'},
                                  {'href': '{}/internal_endpoint_ref'.format(url),
                                   'method': 'GET',
                                   'rel': 'internal_endpoint',
                                   'type': 'internal_endpoint'},
                                  {'href': '{}/gateway_certificate_ref'.format(url),
                                   'method': 'GET',
                                   'rel': 'gateway_certificate',
                                   'type': 'gateway_certificate'},
                                  {'href': '{}/gateway_certificate_request_ref'.format(url),
                                   'method': 'GET',
                                   'rel': 'gateway_certificate_request',
                                   'type': 'gateway_certificate_request'}],
                         'name': 'testfw - Primary'})
    
    def test_internal_gateway_fail(self, m):
        uri = 'internal_gateway'
        
        register_get_and_reply(m, uri, 
                               reply_status=200, 
                               reply_json={},
                               reply_method='GET')
        
        engine = Engine(name='foo', meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertRaises(UnsupportedEngineFeature, lambda: engine.internal_gateway)
    
    def test_internal_gateway_pass(self, m):
        uri = 'internal_gateway'
        
        gw = [{'name': 'sg_vm_vpn', 
               'type': 'internal_gateway', 
               'href': url}]
        
        register_get_and_reply(m, uri, 
                               reply_status=200,
                               reply_method='GET',
                               reply_json=gw)
        
        engine = Engine(name='sg_vm', meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertIsInstance(engine.internal_gateway, InternalGateway)
        self.assertEqual(engine.internal_gateway.name, 'sg_vm_vpn')
    
    def test_vpn_site(self, m):
        
        gateway = self.meta('vpn_site')
        gateway._cache = self.cache()
    
        register_request(m, 'vpn_site', status_code=304)
        res = gateway.vpn_site
        self.assertIsInstance(res, VPNSite)
        self.assertEqual(res.href, '{}/vpn_site'.format(url))
    
    def test_internal_endpoint(self, m):
        
        gateway = self.meta('internal_endpoint')
        gateway._cache = self.cache()
    
        register_request(m, 'internal_endpoint', status_code=304)
        res = gateway.internal_endpoint
        self.assertIsInstance(res, InternalEndpoint)
        self.assertEqual(res.href, '{}/internal_endpoint_ref'.format(url))
        
        endpoint = {'name': '1.1.1.1', 
                    'href': url, 
                    'type': 'internal_endpoint'}
        register_request(m, 'internal_endpoint_ref', 
                         json=[endpoint])
        list_internal_endpoints = res.all()
        self.assertIsInstance(list_internal_endpoints, list)
        self.assertEqual(list_internal_endpoints[0].name, '1.1.1.1')
         
    def test_gateway_certificate(self, m):
        
        gateway = self.meta('gateway_certificate')
        gateway._cache = self.cache()
        
        register_request(m, 'gateway_certificate', status_code=304)
        register_request(m, 'gateway_certificate_ref', 
                         json={})
        self.assertIsInstance(gateway.gateway_certificate(), list)
    
    def test_gateway_certificate_request(self, m):
        
        gateway = self.meta('gateway_certificate_request')
        gateway._cache = self.cache()
        
        register_request(m, 'gateway_certificate_request', status_code=304)
        register_request(m, 'gateway_certificate_request_ref', json={})
        self.assertIsInstance(gateway.gateway_certificate_request(), list)
    
    def test_generate_certificate(self, m):
        
        gateway = self.meta('generate_certificate')
        gateway._cache = self.cache()
        
        register_request(m, 'generate_certificate', status_code=304)
        register_request(m, 'generate_certificate_ref',
                         json={'details': 'failed'},
                         method='POST',
                         status_code=500)
        class cert: pass
        self.assertRaises(CertificateError, lambda: gateway.generate_certificate(cert()))

@requests_mock.Mocker()
class VirtualResourceMocks(unittest.TestCase):
    """
    Tests engine level aliases
    References classes in smc.core.resources
    """
    def setUp(self):
        mysession.login(url, api_key)
        
    def tearDown(self):
        mysession.logout()
    
    def cache(self):
        return ('"NjkwNjAyODExNA=="', {'allocated_domain_ref': url,
                                       'connection_limit': 0,
                                       'link': [],
                                       'name': 've-1',
                                       'show_master_nic': False,
                                       'vfw_id': 1})
      
    def test_create_virtual_resource(self, m):
        
        register_request(m, '{}/elements?exact_match=True&filter_context=admin_domain&filter=Shared+Domain'
                         .format(mysession.api_version), 
                         json=[{"result":[{"href":"{}/admin_domain/1".format(url),
                                           "name":"Shared Domain",
                                           "type":"admin_domain"}]}])
        
        register_request(m, 'virtual_resource', 
                         status_code=200, 
                         json=[], 
                         method='POST')
        
        resource = VirtualResource(meta=Meta(href='{}/virtual_resource'.format(url)))
        self.assertIsInstance(resource.create(name='virtual_fw', vfw_id=10), SMCResult)
    
    def test_class_attributes(self, m):
        # Simulate loading an existing VE from an engine reference
        resource = VirtualResource(meta=Meta(name='ve-1', href='{}/virtual_resource'.format(url)))
        self.assertEqual(resource.name, 've-1')
    
        # When accessing virtual resource from engine view, this is retrieved via
        # engine.virtual_resource and will show an abbreviated version from the master
        # engine view. You can view the entire VE engine json by loading as Engine(ve).
        resource._cache = self.cache()
        
        # Catch call to cache and return 304 (already have current)
        register_request(m, 'virtual_resource', status_code=304)                   
        self.assertDictEqual(resource.describe(), resource._cache[1])
        self.assertEqual(resource.vfw_id, 1)
        
    def test_all(self, m):
        
        resource = VirtualResource(meta=Meta(href='{}/virtual_resource'.format(url)))
        
        # Call to all returns meta data returned from SMC
        json = [{'name':'ve-8', 'href':'{}/virtual_resource/697'.format(url), 'type':'virtual_resource'},
                {'name':'ve-1', 'href':'{}/virtual_resource/690'.format(url), 'type':'virtual_resource'}]
        
        register_request(m, 'virtual_resource', 
                         status_code=200, 
                         json=json)
        names = [name.get('name') for name in json]
        
        for res in resource.all():
            self.assertIn(res.name, names)
            self.assertIsInstance(res, VirtualResource)
       
@requests_mock.Mocker()
class AliasMocks(unittest.TestCase):
    """
    Tests engine level aliases
    References classes in smc.core.resources
    """
    def setUp(self):
        mysession.login(url, api_key)
        
    def tearDown(self):
        mysession.logout()

    def test_alias_pass(self, m):
        # All engine types have aliases
        uri = 'alias_resolving'
        
        # First GET will return the meta JSON
        alias = [{'cluster_ref': 'http://172.18.1.150:8082/6.1/elements/fw_cluster/116', 
                  'resolved_value': ['1.1.1.1'], 
                  'alias_ref': '{}/alias'.format(url)}]
        
        register_get_and_reply(m, uri, 
                               reply_status=200, 
                               reply_json=alias, 
                               reply_method='GET')
        
        # Second request will return the Alias JSON
        alias_resolved = {'name': '$$ Valid DHCP Servers for Mobile VPN clients', 
                          'comment': 'DHCP servers',
                          'link': [{'method': 'GET', 
                                    'href': 'resolve', 
                                    'rel': 'resolve'},      
                                   {'method': 'GET', 
                                    'href': url, 
                                    'rel': 'search_category_tags_from_element'}]
                          }
        
        register_request(m, 'alias', 
                         status_code=200, 
                         json=alias_resolved)
        
        engine = Engine(name='foo', meta=Meta(href='{}/{}'.format(url, uri)))
        for a in engine.alias_resolving():
            self.assertIsInstance(a, Alias)
            self.assertEqual(a.href, '{}/alias'.format(url))
            self.assertIn('1.1.1.1', a.resolved_value)
            self.assertEqual(a.name, '$$ Valid DHCP Servers for Mobile VPN clients')
            self.assertEqual(a.resolve(), 'resolve')

@requests_mock.Mocker()
class RouteMocks(unittest.TestCase):
    """
    Tests engine level references to routing methods;
    engine.routing()
    engine.routing_monitoring()
    References classes in smc.core.resources
    """
    def setUp(self):
        mysession.login(url, api_key)
        
    def tearDown(self):
        mysession.logout()

    def test_routing_pass(self, m):
        uri = 'routing'
        
        route = {'routing_node':
                    [{'exclude_from_ip_counting': False,
                      'href': url,
                      'level': 'interface',
                      'link': [{'href': url,
                                'method': 'GET',
                                'rel': 'self',
                                'type': 'routing'}],
                      'name': 'Interface 0',
                      'nic_id': '0',
                      'routing_node': [{'href': url,
                                        'ip': '172.18.1.0/24',
                                        'level': 'network',
                                        'link': [{'href': url,
                                                  'method': 'GET',
                                                  'rel': 'self',
                                                  'type': 'routing'}],
                                        'name': 'network-172.18.1.0/24',
                                        'routing_node': []}],
                        }]
                 }
                
        register_get_and_reply(m, uri, 
                               reply_status=200, 
                               reply_json=route, 
                               reply_method='GET')
        
        
        engine = Engine(name='foo', meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertIsInstance(engine.routing, Routing)
        for route in engine.routing.all():
            self.assertIsInstance(route, RoutingNode)
            self.assertEqual(route.name, 'Interface 0')
            self.assertIsInstance(route.describe(), dict)
            self.assertIn('172.18.1.0/24', route.network)
   
    def test_routing_monitoring_fail(self, m):
        # Timeout when connecting to node
        uri = 'routing_monitoring'
        register_get_and_reply(m, uri, 
                               reply_status=200, 
                               reply_json=raise_within, 
                               reply_method='GET')
        engine = Engine(name='foo', meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertIsInstance(engine.routing_monitoring, list)
        self.assertTrue(len(engine.routing_monitoring) == 0)
    
    def test_routing_monitoring_pass(self, m):
        uri = 'routing_monitoring'
        
        spoof = {'routing_monitoring_entry': [{
                                          'cluster_ref': url,
                                          'dst_if': 1,
                                          'route_gateway': '10.0.0.1',
                                          'route_netmask': 0,
                                          'route_network': '0.0.0.0',
                                          'route_type': 'Static',
                                          'src_if': -1}]}
        register_get_and_reply(m, uri, 
                               reply_status=200, 
                               reply_json=spoof, 
                               reply_method='GET')
        engine = Engine(name='foo', meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertIsInstance(engine.routing_monitoring, RouteTable)
        for route in engine.routing_monitoring.all():
            self.assertIsInstance(route, Route)
            self.assertEqual(route.gateway, '10.0.0.1')
            self.assertEqual(route.network, '0.0.0.0/0')
            self.assertEqual(route.type, 'Static')
            self.assertEqual(route.src_if, -1)
            self.assertEqual(route.dst_if, 1)

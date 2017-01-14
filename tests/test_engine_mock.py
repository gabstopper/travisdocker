import unittest
from smc import session as mysession
import requests_mock
from constants import url, api_key
from smc.core.engine import Engine, VirtualResource, InternalGateway
from smc.core.interfaces import Interface, PhysicalInterface
from smc.base.model import Meta
from smc.api.exceptions import UnsupportedEngineFeature,\
    UnsupportedInterfaceType, SMCConnectionError, EngineCommandFailed,\
    TaskRunFailed, LoadEngineFailed
from smc.core.resource import RouteTable, Route, Routing, RoutingNode, Alias, Snapshot
from smc.core.node import Node

def register_request(adapter, uri, 
                     status_code=200,
                     json=None, 
                     method='GET',
                     headers={'content-type': 'application/json'}):
    """
    Simple GET request mock. URI should be the 'rel' link for the
    resource under test. Check the method being tested for the rel
    name when find_link_by_name is called.
    """
    # JSON is returned when URI is matched
    json = {'link':[
                    {
                     'href': '{}/{}'.format(url, uri),
                     'method': 'POST',
                     'rel': uri
                     }
                    ]
            } if json is None else json
    
    adapter.register_uri(method, '/{}'.format(uri),
                         json=json,
                         status_code=status_code,
                         headers=headers)

def register_get_and_reply(adapter, uri, 
                           reply_status=200,# status code to return
                           reply_json=None, # return response.json
                           reply_text=None, # return response.content
                           reply_method='POST',
                           reply_headers={'content-type': 'application/json'}):
    """
    Registers the first GET request that will use find_link_by_name
    to retrieve the HREF of the resource. The json returned is the uri 
    provided. 
    The reply method should match the signature of the next function call 
    in the tested method. Most methods involve a GET to find the resource, 
    followed by a GET/PUT/POST to get the resource.
    """
    # Note: href is modified so method response goes to different bound URL
    uri_reply = '{}_reply'.format(uri)  
    adapter.register_uri('GET', '/{}'.format(uri),
                         json={'link':[
                                        {
                                         'href': '{}/{}'.format(url, uri_reply),
                                         'method': 'POST',
                                         'rel': uri
                                         }
                                       ]
                               },
                         status_code=200,
                         headers={'content-type': 'application/json'})
    # Register the URI for the reply to above GET
    # Other attributes are included in the POST/PUT/GET reply
    json = reply_json if reply_json is not None else {}
    if reply_text is not None:
        json = None
    
    adapter.register_uri(reply_method, '/{}'.format(uri_reply),
                         json=json,
                         text=reply_text,
                         status_code=reply_status,
                         headers=reply_headers)

def raise_within(request, context):
    raise SMCConnectionError
    
@requests_mock.Mocker()
class EngineMocks(unittest.TestCase):
    
    def setUp(self):
        mysession.login(url, api_key)
        
    def tearDown(self):
        mysession.logout()
    
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

    def test_antispoofing(self, m):
        uri = 'antispoofing'
        register_get_and_reply(m, uri, 
                               reply_status=200, 
                               reply_json={'test': 'foo'}, 
                               reply_method='GET')
        
        engine = Engine(name='foo', meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertIsInstance(engine.antispoofing(), dict)
        
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
        self.assertRaises(EngineCommandFailed, lambda: engine.generate_snapshot(filename='/'))
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
                         json={'link':[
                                           {
                                            'href': '{}/content'.format(url),
                                            'method': 'POST',
                                            'rel': 'content'
                                            }
                                           ]
                                   }, 
                         )
    
        full_snapshot = {'upload_time': '2017-01-14T13:57:08Z', 
                         'link': [{'href': url, 
                                   'rel': 'content', 
                                   'method': 'GET'}, 
                                  {'type': 'snapshot', 
                                   'href': url, 
                                   'rel': 'self', 
                                   'method': 'GET'}, 
                                  {'href': url, 
                                   'rel': 'search_category_tags_from_element', 
                                   'method': 'GET'}], 
                         'comment': 'Refresh started from REST API', 
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
       
    
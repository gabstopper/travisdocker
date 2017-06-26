import unittest
import requests_mock
from smc.tests.constants import url
from smc.elements.network import Alias
from smc.core.engine import Engine, VirtualResource, InternalGateway
from smc.core.interfaces import Interface, PhysicalInterface
from smc.base.model import SimpleElement
from smc.api.exceptions import UnsupportedEngineFeature,\
    UnsupportedInterfaceType, SMCConnectionError, EngineCommandFailed,\
    TaskRunFailed, CertificateError
from smc.core.resource import Snapshot
from smc.core.route import Routing, Antispoofing, Routes
from smc.tests.mocks import (mock_get_ospf_default_profile,
                             mock_search_get_first_log_server,
                             inject_mock_for_smc)

import logging
from smc.base.collection import SubElementCollection
logging.getLogger()
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s %(name)s.%(funcName)s: %(message)s')


def MockEngine(name='myengine'):
    engine = Engine(name=name,
                    href='{}/engine'.format(url),
                    type='single_fw')
    cache = {'name': 'myengine',
             'nodes': [{'firewall_node': {'activate_test': True,
                                          'engine_version': 'version 6.1 #17028',
                                          'name': 'test node 1',
                                          'nodeid': 1}}],
             'link': [{'href': '{}/internal_gateway'.format(url),
                       'rel': 'internal_gateway'},
                      {'href': '{}/nodes'.format(url),
                       'rel': 'nodes'},
                      {'href': '{}/permissions'.format(url),
                       'rel': 'permissions'},
                      {'href': '{}/blacklist'.format(url),
                       'rel': 'blacklist'},
                      {'href': '{}/flush_blacklist'.format(url),
                       'rel': 'flush_blacklist'},
                      {'href': '{}/add_route'.format(url),
                       'rel': 'add_route'},
                      {'href': '{}/antispoofing'.format(url),
                       'rel': 'antispoofing'},
                      {'href': '{}/alias_resolving'.format(url),
                       'rel': 'alias_resolving'},
                      {'href': '{}/routing'.format(url),
                       'rel': 'routing'},
                      {'href': '{}/routing_monitoring'.format(url),
                       'rel': 'routing_monitoring'},
                      {'href': '{}/virtual_resources'.format(url),
                       'rel': 'virtual_resources'},
                      {'href': '{}/interfaces'.format(url),
                       'rel': 'interfaces'},
                      {'href': '{}/tunnel_interface'.format(url),
                       'rel': 'tunnel_interface'},
                      {'href': '{}/physical_interface'.format(url),
                       'rel': 'physical_interface'},
                      {'href': '{}/virtual_physical_interface'.format(url),
                       'rel': 'virtual_physical_interface'},
                      {'href': '{}/modem_interface'.format(url),
                       'rel': 'modem_interface'},
                      {'href': '{}/adsl_interface'.format(url),
                       'rel': 'adsl_interface'},
                      {'href': '{}/wireless_interface'.format(url),
                       'rel': 'wireless_interface'},
                      {'href': '{}/switch_physical_interface'.format(url),
                       'rel': 'switch_physical_interface'},
                      {'href': '{}/refresh'.format(url),
                       'rel': 'refresh'},
                      {'href': '{}/upload'.format(url),
                       'rel': 'upload'},
                      {'href': '{}/generate_snapshot'.format(url),
                       'rel': 'generate_snapshot'},
                      {'href': '{}/snapshots'.format(url),
                       'rel': 'snapshots'}]
                       }
    engine.data = SimpleElement(etag='abc123456', **cache)
    return engine


def MockInternalGateway():
    internal_gw = {'type': 'internal_gateway',
                   'name': 'testfw - Primary',
                   'href': '{}/internal_gateway'.format(url)}
    gw = InternalGateway(**internal_gw)
    cache = {'antivirus': False,
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
                      'name': 'testfw - Primary'}
    gw.data = SimpleElement(etag='etag', **cache)
    return gw


def MockVirtualResource():
    v = VirtualResource(href='{}/virtual_resource'.format(url),
                        name='ve-1')
    cache = {'allocated_domain_ref': url,
             'connection_limit': 0,
             'link': [],
             'name': 've-1',
             'show_master_nic': False,
             'vfw_id': 1}
    v.data = SimpleElement(etag="NjkwNjAyODExNA==", **cache)
    return v


def raise_within(request, context):
    raise SMCConnectionError


@requests_mock.Mocker()
class EngineMocks(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """ 
        Set up SMC Session object once per test class. Primary reason is
        to load the Mock session object as smc.api.session._session since
        this assumes we will not have a real connection.
        """
        super(EngineMocks, cls).setUpClass()
        inject_mock_for_smc()
        cls.engine = MockEngine()

    def del_cache_item(self, item):
        self.engine.data['link'][:] = [d
                                       for d in self.engine.data['link']
                                       if d.get('rel') != item]

    def test_engine_create(self, m):

        log_servers = list(mock_search_get_first_log_server(m))
        log_server = log_servers[0].href
        # OSPF Default Profile GET when profile not specified, returns META
        mock_get_ospf_default_profile(m)

        engine = Engine._create(name='foo',
                                node_type='firewall_node',
                                physical_interfaces=[
                                    {'virtual_physical_interface': {'aggregate_mode': 'none'}}],
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
                self.assertEqual(nodetype, 'firewall_node')
        self.assertEqual(engine['log_server_ref'], log_server)
        self.assertEqual(engine['location_ref'], url)
        for dns in engine['domain_server_address']:
            self.assertIn(dns.get('value'), ['1.1.1.1', '2.2.2.2'])
        self.assertTrue(engine['dynamic_routing']['ospfv2'].get('enabled'))
        self.assertTrue(engine['dynamic_routing']['ospfv2'].get(
            'ospfv2_profile_ref').startswith(url))

    '''
    def test_load_engine_with_pre61(self, m):

        # Force API version to <6.1
        mysession._cache.api_version = 6.0
        self.assertTrue(mysession._cache.api_version < 6.1)
        
        engine = Engine('myengine') # Reference engine we want
        
        valid_engine = {'name': 'myengine', 
                        'href': '{}/1/engine'.format(url), 
                        'type': 'single_fw'}
    
        # Initial meta href returned from search.element_info_as_json
        engine_j = []
        
        m.get('/elements?filter=myengine&exact_match=True',
              [{'json': engine_j,
                'headers': {'content-type': 'application/json'}}])
        
        # Search came up empty
        self.assertRaises(LoadEngineFailed, lambda: engine.load())
        
        # Multiple search results found
        engine_j.extend([{'name': 'test', 'href': 'blah', 'type': 'foo'},
                         {'name': 'test2', 'href': 'bar', 'type': 'foo'}])
        
        self.assertRaises(LoadEngineFailed, lambda: engine.load())
        
        # Clear engine list
        engine_j[:] = []
        
        # Valid engine
        engine_no_nodes = {'engine_version': 'version 6.1 #17028',
                           'name': 'myengine',
                           'nat_definition': [],
                           'nodes': [],
                           'link': [{'href': '{}/nodes'.format(url),
                                     'rel': 'nodes'}]}
    
        m.get('/1/engine', json=engine_no_nodes,
              status_code=200, headers={'content-type': 'application/json'})

        # Element returned but check to see if its actually and engine type.
        engine_j.append(valid_engine)
        self.assertRaises(LoadEngineFailed, lambda: engine.load())
        
        # Add valid node json to engine level
        engine_no_nodes.get('nodes').append({'firewall_node': {'activate_test': True}})

        engine = engine.load()

        self.assertIsInstance(engine, Engine)
        self.assertEqual(engine.version, engine_no_nodes.get('engine_version'))
        self.assertEqual(engine.type, engine_j[0].get('type'))
        
        # Set node query
        m.get('/nodes', json=[{'name': 'myengine node 1', 
                              'href': '{}/firewall_node'.format(url), 
                              'type': 'firewall_node'}],
              headers={'content-type': 'application/json'})
        
        node = engine.nodes
        self.assertIsInstance(node[0], Node)
        self.assertEqual(node[0].name, 'myengine node 1')
        self.assertEqual(node[0].type, 'firewall_node')
        self.assertEqual(node[0].href, '{}/firewall_node'.format(url))
    
    def test_engine_rename(self, m):
        m.get('/engine', [{'status_code': 304}])
        m.put('/engine', status_code=200)
        
        # Internal gateway interception
        m.get('/internal_gateway', [{'headers': {'content-type': 'application/json'},
                                     'json': [{'name': 'test - Primary', 
                                               'href': '{}/internal_gateway'.format(url), 
                                               'type': 'internal_gateway'}]},
                                    {'headers': {'content-type': 'application/json'},
                                     'status_code': 200,
                                     'json': {'system': False}}])
     
        # Return empty json for success on modify_attribute call
       
        m.get('/nodes', [{'headers': {'content-type': 'application/json'},
                          'json': [{'href': '{}/nodes'.format(url),
                                    'type': 'firewall_node',
                                    'name': 'node1'}]
                          },
                         {'headers': {'content-type': 'application/json'},
                          'json': {'system': False}}]) #Get nodes from engine.cache
        
        self.assertIsNone(self.engine.rename('foo'))
        self.assertEqual(self.engine.name, 'foo')
    '''

    def test_permissions(self, m):

        m.get('/engine', status_code=304)
        m.get('/permissions',
              [{'json': {'granted_access_control_list': [],
                         'cluster_ref': url},
                'headers': {'content-type': 'application/json'}},
               {'status_code': 200}])

        engine = self.engine.permissions
        self.assertIsInstance(engine, list)
        # Not supported engine
        self.del_cache_item('permissions')
        self.assertRaises(UnsupportedEngineFeature,
                          lambda: self.engine.permissions())

    def test_blacklist(self, m):

        m.get('/engine', status_code=304)
        m.post('/blacklist', [{'status_code': 201},
                              {'status_code': 400}])

        j = {'end_point1': {'address_mode': 'address',
                            'ip_network': '1.1.1.2/32', 'name': ''},
             'duration': 3600,
             'end_point2': {'address_mode': 'address',
                            'ip_network': '2.3.4.5/32', 'name': ''}}

        print(self.engine.blacklist('1.1.1.2/32', '2.3.4.5/32'))
        self.assertDictEqual(j, m.last_request.json())
        self.assertRaises(EngineCommandFailed,
                          lambda: self.engine.blacklist('0.0.1.0', '2.3.4.5'))

    def test_blacklist_flush(self, m):

        m.get('/engine', status_code=304)

        m.delete('/flush_blacklist', [{'status_code': 204},
                                      {'status_code': 500}])

        print("Flushing blacklist")
        self.assertIsNone(self.engine.blacklist_flush())

        self.assertRaises(EngineCommandFailed,
                          lambda: self.engine.blacklist_flush())

    def test_add_route(self, m):
        m.get('/engine', status_code=304)
        m.post('/add_route', [{'status_code': 200},
                              {'status_code': 500}])

        query = ['network=1.2.3.4', 'gateway=1.1.1.1']

        self.assertIsNone(self.engine.add_route('1.1.1.1', '1.2.3.4'))

        for qs in m.last_request.query.split('&'):
            self.assertIn(qs, query)
        self.assertRaises(EngineCommandFailed,
                          lambda: self.engine.add_route('blah', 'foo'))

    def test_antispoofing(self, m):
        m.get('/engine', status_code=304)
        m.get('/antispoofing', json={'test': 'foo'},
              headers={'content-type': 'application/json'})

        self.assertIsInstance(self.engine.antispoofing, Antispoofing)

    def test_virtual_resource(self, m):
        m.get('/engine', status_code=304)

        virtual_res = [{'name': 've-2',
                        'href': url,
                        'type': 'virtual_resource'},
                       {'name': 've-3',
                        'href': url,
                        'type': 'virtual_resource'}]

        m.get('/virtual_resources', [{'json': virtual_res,
                                      'headers': {'content-type': 'application/json'},
                                      'status_code': 200},
                                     {'status_code': 200}])

        virtual_res_names = [res.get('name') for res in virtual_res]
        for virtual in self.engine.virtual_resource.all():
            self.assertIsInstance(virtual, VirtualResource)
            self.assertIn(virtual.name, virtual_res_names)

        self.del_cache_item('virtual_resources')
        self.assertRaises(UnsupportedEngineFeature,
                          lambda: self.engine.virtual_resource.all())

    def test_interface(self, m):
        m.get('/engine', status_code=304)

        interfaces = [{'type': 'physical_interface',
                       'href': url,
                       'name': 'Interface 0'},
                      {'type': 'test',
                       'href': url,
                       'name': 'foo'}]

        m.get('/interfaces', json=interfaces,
              headers={'content-type': 'application/json'},
              status_code=200)

        for intf in self.engine.interface.all():
            if intf.name == 'Interface 0':
                self.assertIsInstance(intf, PhysicalInterface)
            else:
                self.assertEqual(intf.name, 'foo')
                self.assertIsInstance(intf, Interface)

    def test_interfaces_pass(self, m):
        m.get('/engine', status_code=304)

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

            m.get('/{}'.format(interface),
                  status_code=200,
                  json=interfaces,
                  headers={'content-type': 'application/json'})

            names = [name.get('name') for name in interfaces]
            pointer = getattr(self.engine, interface).all()
            for intf in pointer:
                # Each class should have 'typeof' attribute
                self.assertEqual(type(intf).typeof, interface)
                self.assertIn(intf.name, names)

    def test_interfaces_fail(self, m):
        # Not supported by specific engine type
        intf = ['tunnel_interface',
                'physical_interface',
                'virtual_physical_interface',
                'switch_physical_interface',
                'wireless_interface',
                'adsl_interface',
                'modem_interface']

        engine = MockEngine()
        for interface in intf:
            m.get('/engine', status_code=304)
            engine.data['link'][:] = [d
                                      for d in engine.data['link']
                                      if d.get('rel') != interface]
            m.get('/{}'.format(interface))
            self.assertRaises(UnsupportedInterfaceType,
                              lambda: getattr(engine, interface))

    def test_unimplemented_interfaces(self, m):
        # Unimplemented interfaces are ones not conforming to interface types defined in
        # test_interfaces_pass. All interfaces will have a similar structure but some very
        # uncommonly used interfaces may not have been implemented and will return generic
        # json data back instead.
        intf = ['modem_interface', 'adsl_interface', 'wireless_interface',
                'switch_physical_interface']
        for interface in intf:
            m.get('/engine', status_code=304)
            m.get('/{}'.format(interface), json=[],
                  headers={'content-type': 'application/json'})
            self.assertIsInstance(getattr(self.engine, interface), list)

    def test_refresh_and_upload(self, m):
        uris = ['refresh', 'upload']

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
            m.get('/engine', status_code=304)
            m.post('/{}'.format(uri), [{'status_code': 200, 'json': task,
                                        'headers': {'content-type': 'application/json'}},
                                       {'status_code': 400}])
            follower = getattr(self.engine, uri)()
            # Test generator and make sure it matches our follower link sent in
            print("Follower: %s" % follower)
            self.assertEqual(follower.follower, task.get('follower'))
            
            # TaskRunFailed
            self.assertRaises(
                TaskRunFailed, lambda: getattr(self.engine, uri)())

    def test_generate_snapshot(self, m):
        m.get('/engine', status_code=304)
        m.get('/generate_snapshot', text='snapshot_content',
              headers={'content-type': 'application/zip'},
              status_code=200)

        # Fail, would raise IOError on web tier due to invalid directory
        self.assertRaises(EngineCommandFailed,
                          lambda: self.engine.generate_snapshot(filename='/'))
        # Success, results stored in smcresult.content attribute
        self.assertIsNone(self.engine.generate_snapshot('blah.txt'))

    def test_snapshot(self, m):

        m.get('/engine', status_code=304)

        result = [{'href': '{}/asnapshot'.format(url),
                   'name': 'Master Engine Policy (2017-01-14 07:57:08)',
                   'type': 'snapshot'}]
        snapshot = [{'name': 'Master Engine Policy (2017-01-14 07:57:08)',
                     'type': 'snapshot',
                     'href': url}]

        m.get('/snapshots', json=result, status_code=200,
              headers={'content-type': 'application/json'})
        m.get('/snapshot', json=snapshot, status_code=200,
              headers={'content-type': 'application/json'})

        snapshot_data = self.engine.snapshots

        self.assertIsInstance(list(snapshot_data), list)
        self.assertIsInstance(list(snapshot_data)[0], Snapshot)
        self.assertEqual(list(snapshot_data)[
                         0].name, list(snapshot)[0].get('name'))

    def test_snapshot_download_pass_and_fail(self, m):
        uri = 'snapshot'

        snapshot_j = {'name': 'Master Engine Policy (2017-01-14 07:57:08)',
                      'type': 'snapshot',
                      'href': '{}/{}'.format(url, uri)}

        snapshot = Snapshot(**snapshot_j)
        self.assertEqual(snapshot.name, snapshot_j.get('name'))

        m.get('/snapshot', status_code=200,
              json={'link': [{'href': '{}/content'.format(url),
                              'rel': 'content'}]},
              headers={'content-type': 'application/json'})

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

        m.get('/content', json=full_snapshot, status_code=200,
              headers={'content-type': 'application/json'})

        self.assertRaises(EngineCommandFailed,
                          lambda: snapshot.download(filename='/'))
        smcresult = snapshot.download()
        # Without filename specific, default save to local directory, use
        # snapshot.name.zip
        self.assertIsNone(smcresult)


@requests_mock.Mocker()
class InternalGatewayMocks(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """ 
        Set up SMC Session object once per test class. Primary reason is
        to load the Mock session object as smc.api.session._session since
        this assumes we will not have a real connection.
        """
        super(InternalGatewayMocks, cls).setUpClass()
        inject_mock_for_smc()
        cls.gw = MockInternalGateway()

    def test_internal_gateway_fail(self, m):

        m.get('/engine', status_code=304)
        m.get('/internal_gateway', [{'status_code': 200,
                                     'headers': {'content-type': 'application/json'},
                                     'json': [{'type': self.gw._meta.type,
                                               'name': self.gw._meta.name,
                                               'href': self.gw._meta.href}]
                                     }
                                    ])
        engine = MockEngine()

        internal_gateway = engine.internal_gateway
        self.assertIsInstance(internal_gateway, InternalGateway)
        self.assertEqual(internal_gateway.name, 'testfw - Primary')

        #del engine._resource.internal_gateway
        engine.data['link'][:] = [d
                                  for d in engine.data['link']
                                  if d.get('rel') != 'internal_gateway']
        self.assertRaises(UnsupportedEngineFeature,
                          lambda: engine.internal_gateway)

    '''    
    def test_vpn_site(self, m):
        
        m.get('/internal_gateway', status_code=304)
        
        res = self.gw.vpn_site
        print(res.all())
        self.assertIsInstance(res, VPNSite)
        self.assertEqual(res.href, '{}/vpn_site'.format(url))
    '''

    def test_internal_endpoint(self, m):

        m.get('/internal_gateway', status_code=304)
        res = self.gw.internal_endpoint
        #self.assertIsInstance(res, InternalEndpoint)
        self.assertIsInstance(res, SubElementCollection)

        self.assertEqual(res.href, '{}/internal_endpoint_ref'.format(url))

        endpoint = {'name': '1.1.1.1',
                    'href': url,
                    'type': 'internal_endpoint'}

        m.get('/internal_endpoint_ref', json=[endpoint],
              headers={'content-type': 'application/json'})

        list_internal_endpoints = list(res.all())
        self.assertIsInstance(list_internal_endpoints, list)
        self.assertEqual(list_internal_endpoints[0].name, '1.1.1.1')

    def test_gateway_certificate(self, m):

        m.get('/internal_gateway', status_code=304)
        m.get('/gateway_certificate_ref', json={},
              headers={'content-type': 'application/json'})
        self.assertIsInstance(self.gw.gateway_certificate(), dict)
        
    def test_gateway_certificate_request(self, m):

        m.get('/internal_gateway', status_code=304)
        m.get('/gateway_certificate_request_ref', json={},
              headers={'content-type': 'application/json'})
        # Empty no data
        self.assertIsInstance(self.gw.gateway_certificate_request(), dict)

    def test_generate_certificate(self, m):

        m.get('/internal_gateway', status_code=304)
        m.post('/generate_certificate_ref', json={'details': 'failed'},
               headers={'content-type': 'application/json'},
               status_code=400)

        class cert:
            pass
        self.assertRaises(CertificateError,
                          lambda: self.gw.generate_certificate(cert()))


@requests_mock.Mocker()
class VirtualResourceMocks(unittest.TestCase):
    """
    Tests engine level aliases
    References classes in smc.core.resources
    """
    @classmethod
    def setUpClass(cls):
        """ 
        Set up SMC Session object once per test class. Primary reason is
        to load the Mock session object as smc.api.session._session since
        this assumes we will not have a real connection.
        """
        super(VirtualResourceMocks, cls).setUpClass()
        inject_mock_for_smc()
        cls.virt = MockVirtualResource()

    def test_create_virtual_resource(self, m):

        print("Creating virtual resource")
        m.get('/elements?exact_match=True&filter_context=admin_domain&filter=Shared+Domain',
              json=[{"result": [{"href": "{}/admin_domain/1".format(url),
                                 "name": "Shared Domain",
                                 "type": "admin_domain"}]}])

        m.post('/virtual_resource', status_code=200, json=[],
               headers={'Location': '{}'.format(url)})
        
        self.assertTrue(self.virt.create(
            name='virtual_fw', vfw_id=10).startswith('http'))
        
    def test_class_attributes(self, m):

        self.assertEqual(self.virt.name, 've-1')
        m.get('/virtual_resource', status_code=304)
        self.assertEqual(self.virt.vfw_id, 1)

    '''   
    def test_all(self, m):
       
        # Call to all returns meta data returned from SMC
        json = [{'name':'ve-8', 'href':'{}/virtual_resource/697'.format(url), 'type':'virtual_resource'},
                {'name':'ve-1', 'href':'{}/virtual_resource/690'.format(url), 'type':'virtual_resource'}]
        
        m.get('/virtual_resource', status_code=200, json=json,
              headers={'content-type': 'application/json'})
       
        names = [name.get('name') for name in json]
        
        for res in self.virt.all():
            self.assertIn(res.name, names)
            self.assertIsInstance(res, VirtualResource)   
    '''


@requests_mock.Mocker()
class AliasMocks(unittest.TestCase):
    """
    Tests engine level aliases
    References classes in smc.core.resources
    """
    @classmethod
    def setUpClass(cls):
        """ 
        Set up SMC Session object once per test class. Primary reason is
        to load the Mock session object as smc.api.session._session since
        this assumes we will not have a real connection.
        """
        super(AliasMocks, cls).setUpClass()
        inject_mock_for_smc()

    def test_alias_pass(self, m):
        # All engine types have aliases

        engine = MockEngine()
        # First GET will return the meta JSON
        alias = [{'cluster_ref': '{}/1'.format(url),
                  'resolved_value': ['1.1.1.1'],
                  'alias_ref': '{}/alias'.format(url)}]

        #[{'status_code': 200, 'json': task,
        #  'headers': {'content-type': 'application/json'}},
        # {'status_code': 400}]

        # m.get('/engine', [{'status_code': 200,
        #                   'headers': {'content-type': 'application/json'}}])
        m.get('/alias_resolving', status_code=200, json=alias,
              headers={'content-type': 'application/json'})

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

        m.get('/alias', status_code=200, json=alias_resolved,
              headers={'content-type': 'application/json'})

        for a in engine.alias_resolving():
            self.assertIsInstance(a, Alias)
            self.assertIn('1.1.1.1', a.resolved_value)
            self.assertEqual(
                a.name, '$$ Valid DHCP Servers for Mobile VPN clients')


@requests_mock.Mocker()
class RouteMocks(unittest.TestCase):
    """
    Tests engine level references to routing methods;
    engine.routing()
    engine.routing_monitoring()
    References classes in smc.core.resources
    """
    @classmethod
    def setUpClass(cls):
        """ 
        Set up SMC Session object once per test class. Primary reason is
        to load the Mock session object as smc.api.session._session since
        this assumes we will not have a real connection.
        """
        super(RouteMocks, cls).setUpClass()
        inject_mock_for_smc()

    def test_routing(self, m):

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

        m.get('/routing', status_code=200, json=route,
              headers={'content-type': 'application/json'})
        m.get('/engine', status_code=304)

        engine = MockEngine()
        self.assertIsInstance(engine.routing, Routing)
        for route in engine.routing.all():
            self.assertIsInstance(route, Routing)
            self.assertEqual(route.name, 'Interface 0')

    def test_routing_monitoring_fail(self, m):
        # Timeout when connecting to node
        m.get('/routing_monitoring', status_code=200, json=raise_within)
        m.get('/engine', status_code=304)

        engine = MockEngine()
        self.assertRaises(EngineCommandFailed,
                          lambda: engine.routing_monitoring)
        #self.assertIsInstance(engine.routing_monitoring, list)
        #self.assertTrue(len(engine.routing_monitoring) == 0)

    def test_routing_monitoring_pass(self, m):

        spoof = {'routing_monitoring_entry': [{
            'cluster_ref': url,
            'dst_if': 1,
            'route_gateway': '10.0.0.1',
            'route_netmask': 0,
            'route_network': '0.0.0.0',
            'route_type': 'Static',
            'src_if': -1}]}
        m.get('/routing_monitoring', status_code=200, json=spoof,
              headers={'content-type': 'application/json'})
        m.get('/engine', status_code=304)

        engine = MockEngine()
        self.assertIsInstance(engine.routing_monitoring, Routes)
        for route in engine.routing_monitoring.all():
            self.assertEqual(route.route_gateway, '10.0.0.1')
            self.assertEqual(route.route_network, '0.0.0.0')
            self.assertEqual(route.route_type, 'Static')
            self.assertEqual(route.src_if, -1)
            self.assertEqual(route.dst_if, 1)

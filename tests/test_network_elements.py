import io
import unittest
import mock
import requests
from smc.tests.constants import url, api_key, verify, is_min_required_smc_version
from smc import session
import smc.actions.search as search
from smc.elements.network import Zone, DomainName, IPList, Host, AddressRange, Router,\
    Network, Expression, URLListApplication
from smc.elements.service import UDPService, ICMPService, ICMPIPv6Service, IPService, TCPService,\
    Protocol, EthernetService
from smc.elements.group import Group, ServiceGroup, TCPServiceGroup, UDPServiceGroup, \
    IPServiceGroup
from smc.elements.other import LogicalInterface, Location, MacAddress,\
    prepare_blacklist, Category, AdminDomain, CategoryTag
from smc.base.model import Element, cached_property, SimpleElement
from smc.api.exceptions import UnsupportedEntryPoint, ElementNotFound,\
    MissingRequiredInput, CreateElementFailed, ModificationFailed,\
    ResourceNotFound, DeleteElementFailed, UpdateElementFailed, TaskRunFailed
from smc.api.common import SMCRequest
from smc.elements.user import AdminUser, ApiClient
from smc.elements.helpers import zone_helper, location_helper,\
    logical_intf_helper
from smc.base.util import merge_dicts, find_link_by_name, element_resolver
from smc.base.collection import Search
from smc.elements.netlink import StaticNetlink, Multilink, multilink_member
from smc.administration.role import Role
from smc.administration.access_rights import AccessControlList, Permission
from smc.vpn.policy import VPNPolicy
from smc.policy.layer3 import FirewallTemplatePolicy
from smc.administration.tasks import DownloadTask

#Counter({'read': 187, 'cache': 162, 'create': 71, 'delete': 57, 'update': 12})

class Test(unittest.TestCase):

    def setUp(self):
        session.login(url=url, api_key=api_key, timeout=120, verify=verify)

    def tearDown(self):
        try:
            session.logout()
        except (SystemExit, requests.exceptions.ConnectionError):
            pass
    
    def test_type_error_in_common(self):
        # Catch TypeError in common. Caused by malformed JSON
        self.assertRaises(TypeError, lambda: SMCRequest(
            href=search.element_entry_point('host'),
            json={'test'}
        ).create())

    def test_get_resource_link_before_cache_called(self):
        Host.create(name='cachehost', address='1.1.1.1')
        h = Host('cachehost')
        self.assertFalse(vars(h).get('_cache'))
        h.data
        cache = vars(h).get('data')
        self.assertIsInstance(cache, SimpleElement)
        h.delete()

    def test_no_typeof_attribute_for_element(self):
        class Blah(Element):
            pass
        self.assertRaises(ElementNotFound, lambda: Blah('test').href)

    def test_element_resolver(self):
        host = Host.create('hostelement', address='1.1.1.1')
        resolved = element_resolver([Host('hostelement'), 'http://2.2.2.2'])
        for r in resolved:
            self.assertIn(r, [host.href, 'http://2.2.2.2'])
        # Catches ElementNotFound in list
        with self.assertRaises(ElementNotFound):
            element_resolver(elements=[Host('foobarblah')])

    def test_element_update_invalid_attribute(self):
        host = Host.create(name='kali', address='1.1.1.1')
        host.address ='34.34.34.34'
        host.commento = 'testcomment' # Invalid attribute
        with self.assertRaises(UpdateElementFailed):
            host.update()
        # This should not remove instance attributes
        with self.assertRaises(AttributeError):
            host.commento
        self.assertEqual(host.address, '1.1.1.1')
        host.delete()
    
    def test_system_element_no_export(self):
        host = Host('ALL-SYSTEMS.MCAST.NET')
        self.assertFalse(host.export())
    
    def test_element_update_valid(self):
        host = Host.create(name='kali', address='1.1.1.1')
        self.assertEqual(host.address, '1.1.1.1')
        host.address ='34.34.34.34'
        host.comment = 'acomment'
        host.update()
        for attr in vars(host).keys():
            self.assertNotEqual(attr, 'address')
            self.assertNotEqual(attr, 'comment')
        self.assertEqual(host.address, '34.34.34.34')
        
    def test_delete_already_deleted_host(self):
        # Verify a stale href that was deleted gives expected error
        Host.create('tyler', '1.1.1.1')
        host = Host('tyler').href
        Host('tyler').delete()
        result = SMCRequest(href=host).delete()
        self.assertIsNotNone(result.msg)

    def test_update_no_etag(self):
        # Failed PUT request
        Host.create('tyler', '1.1.1.1')
        a = Host('tyler')
        element = a.data
        element.update(name='newtyler')
        result = SMCRequest(href=a.href, json=element).update()
        self.assertIsNotNone(result.msg)
        Host('tyler').delete()

    def bad_json_POST(self):
        # If customized json is going through and it's invalid, TypeError is
        # thrown
        href = search.element_entry_point('host')
        self.assertRaises(TypeError, lambda: SMCRequest(
            href=href, json={'ertrte'}).create())
    
    def test_AdminUser_Permissions(self):
        admin = AdminUser.create(name='someadmin', superuser=True)
        self.assertFalse(admin.permissions) #Super user has all privs
        permission = Permission.create(
            granted_elements=[AccessControlList('ALL Firewalls')],
            role=Role('Viewer'))
        admin.add_permission([permission])
       
        self.assertTrue(len(admin.permissions) == 1)
        # Set global true, update will be done automatically
        permission = Permission.create(
            granted_elements=[AccessControlList('ALL Elements')],
            role=Role('Operator'))
        
        admin.add_permission([permission])
        self.assertTrue(len(admin.permissions) == 2)
       
    def test_unknown_host(self):
        host = Host('blahblahblah')
        self.assertRaises(ElementNotFound, lambda: host.href)

    def test_export_element(self):
        # Test exporting a non-system element, should just return href
        result = Host.create('api-export-test', '2.3.4.5')
        self.assertTrue(result.href.startswith('http'))
        host = Host('api-export-test')
        self.assertIsInstance(host.export(), DownloadTask)
        
        with self.assertRaises(TaskRunFailed):
            host.export(filename='/foo').wait()
            
        host.delete()

   
    def test_cache_access_by_class(self):
        self.assertIsInstance(Host.data, cached_property)

    def test_modify_system_element(self):
        # System elements should not be able to be modified
        host = Host('Localhost')
        with self.assertRaises(ModificationFailed):
            host.modify_attribute(name='myLocalhost')

    def test_modify_non_system_element(self):
        # Non system elements can be modified
        result = Host.create('api-test', '2.3.4.5')
        self.assertTrue(result.href.startswith('http'))
        host = Host('api-test')
        result = host.modify_attribute(name='newapi-test')
        self.assertTrue(result.startswith('http'))
        Host('newapi-test').delete()

    def test_load_host_using_meta_dict(self):
        host = Host(name='test', meta={'href': 'http://1.1.1.1'})
        self.assertEqual(host._meta.href, 'http://1.1.1.1')
        self.assertFalse(host._meta.type)
        # Name is not updated when meta is sent as dict
        self.assertFalse(host._meta.name)

    def test_user_creation(self):
        # Create admin user
        result = AdminUser.create(name='smcpython-admin',
                                  local_admin=True,
                                  superuser=True,
                                  enabled=True)
        self.assertTrue(result.href.startswith('http'))
        admin = AdminUser('smcpython-admin')
        self.assertTrue(admin.enabled)
        import time
        time.sleep(2)  # Changing status seems to fail if done quickly
        admin.enable_disable()
        time.sleep(2)
        self.assertFalse(admin.enabled)

        etag = search.element_by_href_as_smcresult(admin.href).etag
        self.assertEqual(admin.etag, etag)

        self.assertIsNone(admin.change_engine_password('password'))
        with self.assertRaises(ModificationFailed):
            admin.change_password('password')
        self.assertIsNone(admin.change_password('123Password!'))
        admin.delete()

    def test_admin_domain(self):
        # No domain license
        with self.assertRaises(CreateElementFailed):
            AdminDomain.create(name='mydomain', comment='mycomment')
    
    def test_api_client(self):
        # ApiClient can be createed in 6.2
        if is_min_required_smc_version('6.2.0'):
            client = ApiClient.create('fooadmin')
            self.assertTrue(client.href.startswith('http'))
            client.delete()
        else:  # API Clients can only be exported in 6.1.1
            client = ApiClient('smcpython')
            self.assertTrue(client.href.startswith('http'))

    #@unittest.skip("good")
    def testHost(self):
        # Create a host and check the etag also
        result = Host.create('api-test', '2.3.4.5')
        self.assertTrue(result.href.startswith('http'))

        # Get Etag
        host = Host('api-test')
        self.assertIsNotNone(host.etag)

        self.assertEqual(host.address, '2.3.4.5')

        self.assertEqual(host.data.get('address'), '2.3.4.5')
        host.modify_attribute(address='1.1.1.1')
        self.assertEqual(host.data.get('address'), '1.1.1.1')
        host.secondary = ['8.8.8.8', '9.9.9.9']
        for ip in host.secondary:
            self.assertIn(ip, ['8.8.8.8', '9.9.9.9'])
        host.ipv6_address = '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
        self.assertEqual(host.ipv6_address,
                         '2001:0db8:85a3:0000:0000:8a2e:0370:7334')
        host.add_secondary(address=['25.25.25.25'], append_lists=True)
        
        self.assertIn('25.25.25.25', host.data.get('secondary'))
        
        with self.assertRaises(AttributeError):
            host.foobarattribute
        
        host.rename('renamedhost')
        self.assertEqual(host.data.get('name'), 'renamedhost')  # Cache refreshed
        host.update(etag=host.etag,
                    name='anothername')
        self.assertEqual(host.name, 'anothername')
        
        host.delete()

    def test_host_using_callable_attribute(self):
        class Address:
            def __call__(self):
                return '123.123.123.123'
        
        host = Host.create('graciebear', address='1.1.1.1')
        self.assertEqual(host.address, '1.1.1.1')
        host.address = Address()
        host.update()
        self.assertEqual(host.address, '123.123.123.123')
        host.delete()
        
    def testHost_no_addresses(self):
        with self.assertRaises(CreateElementFailed):
            Host.create(name='mixedhost')

    def testHost_ipv4_and_ipv6(self):
        result = Host.create(
            name='mixedhost', ipv6_address='2001:cdba::3257:9652', address='1.1.1.1')
        self.assertTrue(result.href.startswith('http'))

        host = Host('mixedhost')
        self.assertEqual(host.address, '1.1.1.1')
        self.assertEqual(host.ipv6_address, '2001:cdba::3257:9652')
        host.delete()

    def test_ipv6host(self):
        result = Host.create(
            name='mixedhost', ipv6_address='2001:cdba::3257:9652')
        self.assertTrue(result.href.startswith('http'))

        host = Host('mixedhost')
        self.assertEqual(host.ipv6_address, '2001:cdba::3257:9652')
        host.delete()

    def test_ipv4_address_with_secondary_ipv6(self):
        result = Host.create(name='mixedhost', address='1.1.1.1', secondary=[
                             '2001:cdba::3257:9652'])
        self.assertTrue(result.href.startswith('http'))

        host = Host('mixedhost')
        self.assertEqual(host.address, '1.1.1.1')
        self.assertIn('2001:cdba::3257:9652', host.secondary)
        host.delete()

    def test_ipv6_address_with_secondary_ipv4(self):
        result = Host.create(
            name='mixedhost', ipv6_address='2001:cdba::3257:9652', secondary=['1.1.1.1'])
        self.assertTrue(result.href.startswith('http'))

        host = Host('mixedhost')
        self.assertEqual(host.ipv6_address, '2001:cdba::3257:9652')
        self.assertIn('1.1.1.1', host.secondary)
        host.delete()

    #@unittest.skip("good")
    def testAddressRange(self):
        result = AddressRange.create('api-iprange', '2.3.4.5-2.3.4.6')
        self.assertTrue(result.href.startswith('http'))

        addr = AddressRange('api-iprange')
        self.assertEqual(addr.ip_range, '2.3.4.5-2.3.4.6')

        self.assertEqual(addr.data.get('ip_range'), '2.3.4.5-2.3.4.6')
        addr.modify_attribute(ip_range='1.1.1.1-1.1.1.2')
        self.assertEqual(addr.data.get('ip_range'), '1.1.1.1-1.1.1.2')
        addr.rename('api-iprange2')
        addr = AddressRange('api-iprange2')
        
        Category.create(name='elements')
        addr.add_category(['elements'])
        for tag in addr.categories:
            self.assertEqual(tag.name, 'elements')
        
        # Add another tag but category doesnt exist so it wil be created automatically
        addr.add_category(['customtag', 'someothertag'])
        for tag in addr.categories:
            self.assertIn(tag.name, ['elements', 'customtag', 'someothertag'])
        
        self.assertIsNone(addr.comment)
        addr.data['comment'] = 'testcomment'
        self.assertEqual(addr.data.get('comment'), 'testcomment')
                        
        addr.delete()

    #@unittest.skip("good")
    def testRouter(self):
        try:
            Router('foorouter').delete()
        except ElementNotFound:
            pass
        result = Router.create('foorouter', '11.1.1.1')
        self.assertTrue(result.href.startswith('http'))
        router = Router('foorouter')
        self.assertEqual(router.data.get('address'), '11.1.1.1')
        router.rename('foorouter2')
        router = Router('foorouter2')
        router.delete()

    def test_router_ipv4_address_with_secondary_ipv6(self):
        result = Router.create(name='mixedhost', address='1.1.1.1',
                               secondary_ip=['2001:cdba::3257:9652'])
        self.assertTrue(result.href.startswith('http'))

        router = Router('mixedhost')
        self.assertEqual(router.address, '1.1.1.1')
        self.assertIn('2001:cdba::3257:9652', router.secondary)
        router.delete()

    def test_router_ipv6_address_with_secondary_ipv4(self):
        result = Router.create(name='mixedhost',
                               ipv6_address='2001:cdba::3257:9652',
                               secondary_ip=['1.1.1.1'])
        self.assertTrue(result.href.startswith('http'))

        router = Router('mixedhost')
        self.assertEqual(router.ipv6_address, '2001:cdba::3257:9652')
        self.assertIn('1.1.1.1', router.secondary)
        router.delete()

    #@unittest.skip("good")
    def testNetwork(self):
        # Invalid host bits
        with self.assertRaises(CreateElementFailed):
            Network.create('foonetwork', '12.1.1.1/24', 'comment')

        Network.create('foonetwork', ipv4_network='12.1.1.0/24',
                       ipv6_network='2001:db8:abcd:12::/64')
        
        network = Network('foonetwork')
        self.assertEqual(network.ipv4_network, '12.1.1.0/24')
        self.assertEqual(network.ipv6_network, '2001:db8:abcd:12::/64')
        network.rename('foonetwork2')
        network = Network('foonetwork2')
        network.delete()

        # Not CIDR format
        with self.assertRaises(CreateElementFailed):
            Network.create('foonetwork', '12.1.1.0/255.255.255.0')

    def test_network_ipv6(self):
        network = Network.create(name='mixednetwork', ipv6_network='fc00::/7')
        self.assertTrue(network.href.startswith('http'))

        network = Network('mixednetwork')
        self.assertEqual(network.ipv6_network, 'fc00::/7')
        network.delete()

    def test_network_ipv6_and_ipv4(self):
        network = Network.create(name='mixednetwork', ipv4_network='12.12.12.0/24',
                                 ipv6_network='fc00::/7')
        self.assertTrue(network.href.startswith('http'))

        network = Network('mixednetwork')
        self.assertEqual(network.ipv6_network, 'fc00::/7')
        self.assertEqual(network.ipv4_network, '12.12.12.0/24')
        network.delete()

    #@unittest.skip("good")
    def testGroup(self):
        # Member not href
        with self.assertRaises(CreateElementFailed):
            Group.create('foogroup', ['test'], 'comment')

        # Same as above
        with self.assertRaises(CreateElementFailed):
            Group.create('foogroup', ['172.18.1.80'])

        # Empty group
        group = Group.create('foogroup')
        self.assertTrue(group.href.startswith('http'))

        # Get context
        group = Group('foogroup')

        # Members
        Host.create('groupmember', '1.1.1.1')
        Network.create(name='anetwork', ipv4_network='1.1.1.0/24')

        self.assertIsNone(group.update_members(members=[Host('groupmember')]))
        # ETag in cache matches server after update
        etag = search.element_by_href_as_smcresult(group.href).etag
        self.assertEqual(group.etag, etag)

        # Get the members back and verify
        for member in group.obtain_members():
            self.assertIn(member.name, ['groupmember'])

        # Check Host has a reference to group
        refs = Host('groupmember').referenced_by
        self.assertEqual(refs[0].name, 'foogroup')

        # Add second member and append
        group.update_members(members=[Network('anetwork')], append_lists=True)
        members = group.obtain_members()
        self.assertTrue(len(members) == 2)
        etag = search.element_by_href_as_smcresult(group.href).etag
        self.assertEqual(group.etag, etag)

        # Overwrite (test sending in as a href)
        group.update_members(members=[Host('groupmember').href], append_lists=False)
        members = group.obtain_members()
        self.assertTrue(len(members) == 1)
        self.assertEqual(members[0].name, 'groupmember')
        etag = search.element_by_href_as_smcresult(group.href).etag
        self.assertEqual(group.etag, etag)

        # Delete all members
        group.empty_members()
        self.assertTrue(len(group.obtain_members()) == 0)
        group.rename('group2')
        # Delete
        Host('groupmember').delete()
        group = Group('group2')
        group.delete()

    def testLocation(self):
        locations = list(Search('location').objects.filter('api-location'))
        if locations:
            self.assertIsNone(locations[0].delete())

        if session.api_version <= 6.0:
            self.assertRaises(UnsupportedEntryPoint,
                              lambda: Location.create('api-location'))
        else:
            result = Location.create('api-location')
            self.assertTrue(result.href.startswith('http'))
            location = Location('api-location')
            # No references but test the method that returns list
            if is_min_required_smc_version('6.2.0'):
                self.assertFalse(location.used_on)
            location.delete()

    #@unittest.skip("good")
    def testZone(self):

        result = Zone.create('api-zone')
        self.assertTrue(result.href.startswith('http'))
        Zone('api-zone').delete()

    #@unittest.skip("good")
    def testLogicalInterface(self):

        result = LogicalInterface.create('api-logical-interface')
        self.assertTrue(result.href.startswith('http'))
        r = LogicalInterface('api-logical-interface')
        self.assertEqual(r.name, 'api-logical-interface')
        r.delete()

    #@unittest.skip("good")
    def testDomainName(self):
        result = DomainName.create('www.lepages.net')
        self.assertTrue(result.href.startswith('http'))
        dn = DomainName('www.lepages.net')
        self.assertEqual(dn.name, 'www.lepages.net')
        dn.delete()

    def testMacAddress(self):
        result = MacAddress.create(
            name='mymac', mac_address='22:22:22:22:22:22')
        self.assertTrue(result.href.startswith('http'))

        obj = MacAddress('mymac')
        self.assertEqual(obj.address, '22:22:22:22:22:22')
        obj.delete()

    def test_prepareblacklist(self):
        result = prepare_blacklist('1.1.1.1/32', '0.0.0.0/0')
        self.assertIsInstance(result, dict)
        self.assertEqual(result.get('end_point1').get(
            'ip_network'), '1.1.1.1/32')
        self.assertEqual(result.get('end_point2').get(
            'ip_network'), '0.0.0.0/0')

    #@unittest.skip("good")
    def test_Expression(self):
        # Test creating an expression

        Host.create('host9', '9.9.9.9')
        Host.create('host10', '10.10.10.10')
        host9 = Host('host9')
        host10 = Host('host10')
        sub_expression = Expression.build_sub_expression(
            name='mytestexporession',
            ne_ref=[host9.href,
                    host10.href],
            operator='union')

        expression = Expression.create(name='pythonexpression',
                                       ne_ref=[],
                                       sub_expression=sub_expression)
        self.assertTrue(expression.href.startswith('http'))
        expr = Expression('pythonexpression')
        expr.delete()
        host9.delete()
        host10.delete()

    #@unittest.skip("good")
    def testTCPService(self):

        result = TCPService.create(
            'api-tcpservice', 5000, 5005, comment='blahcomment')
        self.assertTrue(result.href.startswith('http'))

        service = TCPService('api-tcpservice')
        self.assertEqual(service.min_dst_port, 5000)
        self.assertEqual(service.max_dst_port, 5005)
        service.delete()
    
    def test_tcp_service_with_protocol_agent(self):
        result = TCPService('HTTP')
        self.assertIsInstance(result.protocol_agent, Protocol)

    #@unittest.skip("good")
    def testUDPService(self):

        service = UDPService.create(
            'api-udpservice', 5000, 5005, comment='blahcomment')
        
        self.assertEqual(service.min_dst_port, 5000)
        self.assertEqual(service.max_dst_port, 5005)
        self.assertEqual(service.comment, 'blahcomment')
        self.assertIsNone(service.protocol_agent)

        service.delete()

    def test_udp_service_with_protocol(self):
        p = UDPService('DNS (UDP)')
        self.assertIsInstance(p.protocol_agent, Protocol)
    
    #@unittest.skip("good")
    def testICMPService(self):

        result = ICMPService.create('api-icmp', 3)
        self.assertTrue(result.href.startswith('http'))

        service = ICMPService('api-icmp')
        self.assertEqual(service.icmp_type, 3)
        service.delete()

        result = ICMPService.create('api-icmp', 3, 7, comment='api comment')
        self.assertTrue(result.href.startswith('http'))

        service = ICMPService('api-icmp')
        self.assertEqual(service.icmp_type, 3)
        self.assertEqual(service.icmp_code, 7)
        self.assertEqual(service.comment, 'api comment')
        service.delete()

    #@unittest.skip("good")
    def testIPService(self):

        result = IPService.create('api-ipservice', 93)
        self.assertTrue(result.href.startswith('http'))

        service = IPService('api-ipservice')
        self.assertEqual(service.protocol_number, '93')
        service.delete()
    
    def test_ip_service_with_protocol_agent(self):
        
        service = IPService('GRE')
        self.assertIsInstance(service.protocol_agent, Protocol)

    #@unittest.skip("good")
    def test_ICMPv6Service(self):

        result = ICMPIPv6Service.create('api-Neighbor Advertisement Message', 139,
                                        comment='api-test')
        self.assertTrue(result.href.startswith('http'))

        service = ICMPIPv6Service('api-Neighbor Advertisement Message')
        self.assertEqual(service.icmp_type, 139)
        self.assertEqual(service.comment, 'api-test')

        service.delete()

    def testEthernetService(self):
        if is_min_required_smc_version('6.1.2'):
            result = EthernetService.create(name='myService',
                                            ethertype='32828')
            self.assertTrue(result.href.startswith('http'))
            EthernetService('myService').delete()

    #@unittest.skip("good")
    def testServiceGroup(self):
        """ Test service group creation """
        result = TCPService.create('api-tcp', 5000)
        self.assertTrue(result.href.startswith('http'))

        result = UDPService.create('api-udp', 5001)
        self.assertTrue(result.href.startswith('http'))

        tcp = TCPService('api-tcp')
        udp = UDPService('api-udp')
        result = ServiceGroup.create('api-servicegroup',
                                     members=[tcp.href, udp.href],
                                     comment='test')
        self.assertTrue(result.href.startswith('http'))

        group = ServiceGroup('api-servicegroup')
        # Href in service group
        self.assertIn(tcp.href, group.element)
        self.assertIn(udp.href, group.element)

        group.delete()
        tcp.delete()
        udp.delete()

    #@unittest.skip("good")
    def testTCPServiceGroup(self):

        tcp = TCPService.create('api-tcp', 5000)
        self.assertTrue(tcp.href.startswith('http'))

        tcp2 = TCPService.create('api-tcp2', 5001)
        self.assertTrue(tcp2.href.startswith('http'))

        result = TCPServiceGroup.create('api-tcpservicegroup',
                                        members=[tcp.href, tcp2.href])
        self.assertTrue(result.href.startswith('http'))

        group = TCPServiceGroup('api-tcpservicegroup')
        self.assertIn(tcp.href, group.element)
        self.assertIn(tcp2.href, group.element)

        group.delete()
        tcp.delete()
        tcp2.delete()

    def testUDPServiceGroup(self):

        udp = UDPService.create('udp-svc1', 5000)
        self.assertTrue(udp.href.startswith('http'))

        udp2 = UDPService.create('udp-svc2', 5001)
        self.assertTrue(udp2.href.startswith('http'))

        group = UDPServiceGroup.create('api-udpservicegroup',
                                        members=[udp.href, udp2.href])
        self.assertTrue(group.href.startswith('http'))

        self.assertIn(udp.href, group.element)
        self.assertIn(udp2.href, group.element)

        group.delete()
        udp.delete()
        udp2.delete()

    def testIPServiceGroup(self):

        ipsvc = IPService.create('api-service', 93)
        self.assertTrue(ipsvc.href.startswith('http'))

        ipsvc2 = IPService.create('api-service2', 90)
        self.assertTrue(ipsvc2.href.startswith('http'))

        group = IPServiceGroup.create('api-ipservicegroup',
                                       members=[ipsvc.href, ipsvc2.href],
                                       comment='mygroup')
        self.assertTrue(group.href.startswith('http'))

        self.assertIn(ipsvc.href, group.element)
        self.assertIn(ipsvc2.href, group.element)

        group.delete()
        ipsvc.delete()
        ipsvc2.delete()

    def test_IPList_createWithJson(self):
        if session.api_version >= 6.1:
            try:
                iplist = IPList('smcpython-iplist')
                iplist.delete()
            except ElementNotFound:
                pass

            ips = ['1.1.1.1', '2.2.2.2']
            ip = IPList.create(name='smcpython-iplist', iplist=ips)
            self.assertTrue(ip.href.startswith('http'))

    def test_download_IPList_as_text(self):
        if session.api_version >= 6.1:
            location = list(
                Search('ip_list').objects.filter('smcpython-iplist'))
            if location:
                iplist = location[0]
                result = iplist.download(filename='iplist.txt', as_type='txt')
                self.assertIsNone(result)

    def test_FAILED_download_IPList_as_text(self):
        # Fails if directory doesnt exist or is a directory
        if session.api_version >= 6.1:
            location = list(
                Search('ip_list').objects.filter('smcpython-iplist'))
            if location:
                iplist = location[0]
                with self.assertRaises(IOError):
                    iplist.download(filename='/blah/ahagsd/iplist.txt',
                                    as_type='txt')

    def test_download_IPList_as_zip(self):
        if session.api_version >= 6.1:
            location = list(
                Search('ip_list').objects.filter('smcpython-iplist'))
            if location:
                iplist = location[0]
                result = iplist.download(filename='iplist.zip', as_type='zip')
                self.assertIsNone(result)
                # Require the filename, will fail
                with self.assertRaises(MissingRequiredInput):
                    iplist.download(as_type='zip')

    def test_download_IPList_as_json(self):

        if session.api_version >= 6.1:
            location = list(
                Search('ip_list').objects.filter('smcpython-iplist'))
            iplist = location[0]
            result = iplist.download(as_type='json')
            # Version 6.1.2 has a problem when JSON is NOT returned when
            # specifying application/json headers
            if is_min_required_smc_version('6.1.2'):
                self.assertIsNone(result)
            else:
                ips = ['1.1.1.1', '2.2.2.2']
                print('ips: %s, result: %s' % (ips, result.json))
                self.assertEqual(ips, result.json.get('ip'))

    #@mock.patch('smc.elements.network.open', create=True)
    def test_upload_IPList_as_zip(self):
        if session.api_version >= 6.1:

            #zf = zipfile.ZipFile(io.BytesIO(), "a", zipfile.ZIP_DEFLATED, False)
            # Write the file to the in-memory zip
            #zf.writestr('ip_addresses', '1.1.1.1\n2.2.2.2\n3.3.3.3')
            # print(zf)

            #mock_open.return_value = ('iplist.zip', zf)
            iplist = None
            location = list(
                Search('ip_list').objects.filter('smcpython-iplist'))
            if location:
                iplist = location[0]
            else:
                iplist = IPList.create(name='smcpython-iplist')
                self.assertTrue(iplist.href.startswith('http'))
                
            result = iplist.upload(filename='iplist.zip')
            self.assertIsNone(result)

    @mock.patch('smc.elements.network.open', create=True)
    def test_upload_IPList_as_txt(self, mock_open):
        if session.api_version >= 6.1:
            cfg = ("1.1.1.1\n2.2.2.2")
            mock_open.return_value = io.StringIO(u'{}'.format(cfg))
            iplist = None
            location = list(
                Search('ip_list').objects.filter('smcpython-iplist'))
            if location:
                iplist = location[0]
            else:
                iplist = IPList.create(name='smcpython-iplist')
                self.assertTrue(iplist.href.startswith('http'))

            result = iplist.upload(filename='iplist.txt', as_type='txt')
            self.assertIsNone(result)
            iplist.delete()

    def test_upload_IPList_as_json(self):
        if session.api_version >= 6.1:
            location = list(
                Search('ip_list').objects.filter('smcpython-iplist'))
            if location:
                iplist = location[0]
                result = iplist.upload(json={'ip': ['1.1.1.1', '2.2.2.2', '3.3.3.3']},
                                       as_type='json')
                self.assertIsNone(result)

                with self.assertRaises(CreateElementFailed):
                    iplist.upload(json={'ip': ['1.1.1.1a']},
                                  as_type='json')

        for iplist in list(Search('ip_list').objects.filter('smcpython-iplist')):
            iplist.delete()

    @mock.patch('smc.elements.network.open', create=True)
    def test_upload_IPList_fails_and_raisesException(self, mock_open):
        """
        Invalid format of IP List file
        """
        cfg = ("blah")
        mock_open.return_value = io.StringIO(u'{}'.format(cfg))
        iplist = IPList('smcpython-iplist')
        with self.assertRaises(CreateElementFailed):
            iplist.upload(filename='iplist.zip')

    def test_URLApplication(self):
        # URL List Application
        urllist = URLListApplication.create(name='whitelist',
                                           url_entry=['www.google.com', 'www.cnn.com'])
        self.assertTrue(urllist.href.startswith('http'))
        urllist.delete()

    ###
    # TEST UTILS
    ###
    def test_zone_helper(self):
        result = zone_helper('foozone')
        self.assertTrue(result.startswith('http'))
        Zone('foozone').delete()

    def test_location_helper(self):
        result = location_helper('foolocation')
        self.assertTrue(result.startswith('http'))
        Location('foolocation').delete()

    def test_logical_interface_helper(self):
        intf = logical_intf_helper('foointerface')
        self.assertTrue(intf.startswith('http'))
        LogicalInterface('foointerface').delete()

    def test_merge_dicts_smc_base_util(self):
        # Merge in entry that doesnt exist
        dict1 = {'node': {'subnode1': 'value1',
                          'subnode2': {'node2base': 'value2'}}}

        merge_dicts(dict1, {'node2': 'subnode3'})
        self.assertEqual(dict1.get('node2'), 'subnode3')

        # Merge top level nested dict in
        dict1 = {'node': {'subnode1': 'value1',
                          'subnode2': {'node2base': 'value2'}}}

        merge_dicts(dict1, {'node2': {'subnode3': 'value2'}})
        top = dict1.get('node2')
        self.assertEqual(top.get('subnode3'), 'value2')

        # Validate overwriting dict list
        dict1 = {'node': {'subnode1': 'value1',
                          'subnode2': [1, 2, 3, 4, 5]}}

        merge_dicts(dict1, {'node': {'subnode2': [1, 2]}})
        top = dict1.get('node')
        self.assertTrue(len(top.get('subnode2')) == 2)
        for item in top.get('subnode2'):
            self.assertIn(item, [1, 2])

        # Validate extending existing list
        dict1 = {'node': {'subnode1': 'value1',
                          'subnode2': [1, 2, 3, 4, 5]}}

        merge_dicts(dict1, {'node': {'subnode2': [6, 7]}}, append_lists=True)
        top = dict1.get('node')
        self.assertTrue(len(top.get('subnode2')) == 7)
        self.assertIn(6, top.get('subnode2'))
        self.assertIn(7, top.get('subnode2'))

        # Append to list but original list isn't there
        dict1 = {'node': {'subnode1': 'value1',
                          'subnode2': {'node2base': 'value2'}}}

        merge_dicts(dict1, {'node': {'subnode3': [1, 2]}}, append_lists=True)
        top = dict1.get('node')
        self.assertEqual(top.get('subnode3'), [1, 2])

        # Add subnode dict with list
        dict1 = {'node': {'subnode1': 'value1',
                          'subnode2': {'node2base': 'value2'}}}
        merge_dicts(dict1, {'node': {'subnode3': [1, 2]}})
        top = dict1.get('node')
        self.assertIsInstance(top.get('subnode3'), list)
        self.assertTrue(len(top.get('subnode3')) == 2)

    def test_category_tag(self):
        category = Category.create('foo', comment='mycomment')
        self.assertTrue(category.href.startswith('http'))

        category = Category('foo')
        
        host = Host.create(name='categoryelement', address='1.1.1.1')
        # Add category tag by HREF
        result = category.add_element(host)
        self.assertIsNone(result)

        # Search result
        result = category.search_elements()
        self.assertTrue(result)  # Not []
        self.assertTrue(result[0].name == 'categoryelement')

        # Find the category tag from the element
        result = Host('categoryelement').categories
        self.assertTrue(result)
        self.assertTrue(result[0].name == 'foo')

        # Remove category
        result = category.remove_element(host)
        self.assertIsNone(result)

        # Add by smc.base.model.Element
        result = category.add_element(Host('categoryelement'))
        self.assertIsNone(result)

        # Search result
        result = category.search_elements()
        self.assertTrue(result)  # Not []
        self.assertTrue(result[0].name == 'categoryelement')

        # Delete result by smc.base.model.Element
        result = category.remove_element(Host('categoryelement'))
        self.assertIsNone(result)

        category_tag = CategoryTag.create(name='footag') 
        category.add_category_tag([category_tag.href])
        
        for tag in category.categories:
            self.assertEqual(tag.name, 'footag')
        
        with self.assertRaises(DeleteElementFailed):
            Category('foo').delete() #Dependencies
            
        category_tag = Element.from_href(category_tag.href)
        for category in category_tag.child_categories:
            self.assertTrue(category.name, 'foo')
        
        self.assertFalse(category_tag.parent_categories)
        
        # Throwing when __setattr__ set
        category_tag.remove_category([Category('foo')])
        
        Host('categoryelement').delete()
        Category('foo').delete()
    
    def test_find_link_by_name(self):
        with self.assertRaises(ResourceNotFound):
            find_link_by_name('foo', [])

    def test_multilink_member(self):
        Network.create(name='comcast', ipv4_network='10.10.0.0/16')
        Router.create(name='nexthop', address='10.10.1.254')
    
        StaticNetlink.create(name='isp1', 
                             gateway=Router('nexthop'), 
                             network=[Network('comcast')], 
                             probe_address=['10.10.0.1'])
        
        member1 = multilink_member(
                    StaticNetlink('isp1'),
                    nat_range='10.10.0.1-10.10.0.1')
        
        self.assertEqual(member1['ip_range'], '10.10.0.1-10.10.0.1')
        self.assertEqual(member1['netlink_ref'], StaticNetlink('isp1').href)
        self.assertEqual(member1['netlink_role'], 'active')
        self.assertEqual(member1['network_ref'], Network('comcast').href)
        
        # Add a second member to the static netlink
        n = StaticNetlink('isp1')
        Network.create('att', ipv4_network='192.168.1.0/24')
        n.add_network(Network('att'))
        
        # creating a multilink member fails when there are more than one
        # networks defined and one has not been specified
        with self.assertRaises(MissingRequiredInput):
            multilink_member(
                StaticNetlink('isp1'),
                nat_range='10.10.0.1-10.10.0.1')
        
        # Now provide that specific network
        member1 = multilink_member(
            StaticNetlink('isp1'),
            nat_range='192.168.1.1-192.168.1.1',
            netlink_network=Network('att'))
        
        self.assertEqual(member1['ip_range'], '192.168.1.1-192.168.1.1')
        self.assertEqual(member1['netlink_ref'], StaticNetlink('isp1').href)
        self.assertEqual(member1['netlink_role'], 'active')
        self.assertEqual(member1['network_ref'], Network('att').href)
    
        m = Multilink.create(name='testmultilink', 
            multilink_members=[member1])
        self.assertTrue(m.href.startswith('http'))
        
        Multilink('testmultilink').delete()
        StaticNetlink('isp1').delete()
        Network('comcast').delete()
        Network('att').delete()
        Router('nexthop').delete()
    
    def test_role(self):
        r = Role.duplicate(name='tmprole',
                           role=Role('Superuser'))
        self.assertTrue(r.href.startswith('http'))
        role = Role('tmprole')
    
        role.enable(['view_audit', 'backup_mgmt'])
        for permission in role.permissions:
            for p, value in permission.items():
                if p == 'view_audit':
                    self.assertTrue(value)
                elif p == 'backup_mgmt':
                    self.assertTrue(value)
        role.disable(['view_audit', 'backup_mgmt'])
        for permission in role.permissions:
            for p, value in permission.items():
                if p == 'view_audit':
                    self.assertFalse(value)
                elif p == 'backup_mgmt':
                    self.assertFalse(value)
        
        AdminUser.create(name='myadmin', superuser=True)
        admin = AdminUser('myadmin')
        self.assertFalse(admin.permissions)
        
        permission = Permission.create(
            granted_elements=[AccessControlList('ALL Firewalls')],
            role=role) # Shared Domain
        
        admin.add_permission([permission])
        # Add another to test appending
        
        permission = Permission.create(
            granted_elements=[AccessControlList('ALL Firewalls')],
            role=Role('Viewer'))
        
        self.assertIsInstance(permission, Permission)
        self.assertEqual(permission.granted_domain_ref.href, AdminDomain('Shared Domain').href)
        self.assertEqual(permission.role_ref.href, Role('Viewer').href)
        self.assertEqual(permission.granted_elements[0].href, AccessControlList('ALL Firewalls').href)
        
        admin.add_permission([permission])
        
        self.assertTrue(len(admin.permissions) == 2)
    
    def test_access_control_list(self):
        b = AccessControlList.create(name='restricted')
        policy = FirewallTemplatePolicy.objects.first()
        b.add_permission([policy])
        self.assertTrue(len(b.permissions) == 1)
        b.remove_permission([policy])
        self.assertFalse(b.permissions)
        
    def test_get_or_create_element(self):
        
        # Will be created anew
        host = Host.get_or_create(
            filter_key={'address': '123.123.123.123'},
            name='kookoo',
            address='123.123.123.123')
        
        self.assertEqual(host.name, 'kookoo')
        self.assertEqual(host.data.get('address'), '123.123.123.123')
        
        # Will be retrieved
        host = Host.get_or_create(filter_key={'address': '123.123.123.123'},
                                  name='fooboo',
                                  address='123.123.123.123')
        self.assertEqual(host.name, 'kookoo')
        host.delete()

        # Test the two types using meta characters
        network = Network.get_or_create(
            filter_key={'ipv4_network': '172.18.33.0/24'},
            name='mynetwork',
            ipv4_network='172.18.33.0/24')
        
        self.assertEqual(network.name, 'mynetwork')
        self.assertEqual(network.ipv4_network, '172.18.33.0/24')
        
        network = Network.get_or_create(
            filter_key={'ipv4_network': '172.18.33.0/24'},
            name='mynetwork',
            ipv4_network='172.18.33.0/24')
        self.assertEqual(network.name, 'mynetwork')
        network.delete()
        
        # Address Range
        iprange = AddressRange.get_or_create(
            filter_key={'ip_range': '1.1.1.1-1.1.1.10'},
            name='myrange',
            ip_range='1.1.1.1-1.1.1.10')
        
        self.assertEqual(iprange.name, 'myrange')
        self.assertEqual(iprange.data.get('ip_range'), '1.1.1.1-1.1.1.10')
        
        iprange = AddressRange.get_or_create(
            filter_key={'ip_range': '1.1.1.1-1.1.1.10'},
            name='myrange',
            ip_range='1.1.1.1-1.1.1.10')
        
        self.assertEqual(iprange.name, 'myrange')
        iprange.delete()
        
        vpn = VPNPolicy.get_or_create(name='somepolicy')
        self.assertEqual(vpn.name, 'somepolicy')
        
        tcp = TCPService.get_or_create(
            filter_key={'min_dst_port': 8989},
            name='myservice',
            min_dst_port=8989)
        self.assertIsInstance(tcp, TCPService)
        self.assertEqual(tcp.name, 'myservice')
        
        tcp = TCPService.get_or_create(
            filter_key={'min_dst_port': 8989},
            name='newservice',
            min_dst_port=8989)
        
        self.assertEqual(tcp.name, 'newservice')
        
        host = Host.get_or_create(name='grace', address='12.12.12.12')
        self.assertEqual(host.name, 'grace')
        
        # Already exists
        host = Host.get_or_create(name='grace', address='12.12.12.12')
        self.assertEqual(host.name, 'grace')
    
    def test_update_or_create(self):
        
        host = Host.update_or_create(name='autohost', address='1.1.1.1')
        self.assertEqual(host.name, 'autohost')
        self.assertEqual(host.address, '1.1.1.1')
        
        host = Host.update_or_create(name='autohost', address='2.2.2.2')
        self.assertEqual(host.name, 'autohost')
        self.assertEqual(host.address, '2.2.2.2')
        host.delete()
        
        network = Network.update_or_create(filter_key={'ipv4_network': '192.168.10.0/24'},
                                           name='somenetwork',
                                           ipv4_network='192.168.10.0/24')
        self.assertEqual(network.name, 'somenetwork')
        self.assertEqual(network.ipv4_network, '192.168.10.0/24')
        
        network = Network.update_or_create(filter_key={'ipv4_network': '192.168.10.0/24'},
                                           name='someothernetwork',
                                           ipv4_network='192.168.11.0/24')
        
        self.assertEqual(network.name, 'someothernetwork')
        self.assertEqual(network.ipv4_network, '192.168.11.0/24')
        network.delete()
        
                      
if __name__ == "__main__":
    unittest.main()

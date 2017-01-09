import unittest
from constants import url, api_key, verify
from smc import session
import smc.actions.search as search
from smc.elements.network import Zone, DomainName, IPList, Host, AddressRange, Router,\
    Network, Expression, URLListApplication
from smc.elements.service import UDPService, ICMPService, ICMPIPv6Service, IPService, TCPService,\
    Protocol
from smc.elements.group import Group, ServiceGroup, TCPServiceGroup, UDPServiceGroup, \
    IPServiceGroup
from smc.elements.other import LogicalInterface, Location, MacAddress,\
    prepare_blacklist, prepare_contact_address
from smc.elements.collection import describe_tcp_service,\
    describe_udp_service, describe_service_group, describe_ip_service,\
    describe_ip_service_group, describe_tcp_service_group,\
    describe_network, describe_ip_list, describe_location
from smc.base.model import Element
from smc.api.exceptions import UnsupportedEntryPoint, ElementNotFound,\
    MissingRequiredInput, TaskRunFailed
from smc.api.common import SMCRequest
from smc.api.web import SMCResult
from smc.elements.user import AdminUser, ApiClient
from smc.elements.helpers import zone_helper, location_helper,\
    logical_intf_helper
from smc.administration.tasks import TaskMonitor, TaskDownload


class Test(unittest.TestCase):

    def setUp(self):
        session.login(url=url, api_key=api_key, timeout=120, verify=verify)
    
    def tearDown(self):
        try:
            session.logout()
        except SystemExit:
            pass
    
    def test_type_error_in_common(self):
        # Catch TypeError in common. Caused by malformed JSON
        self.assertRaises(TypeError, lambda: SMCRequest(href=search.element_entry_point('host'),
                                                        json={'test'}).create())
                   
    def test_no_typeof_attribute_for_element(self):
        class Blah(Element):
            pass
        self.assertRaises(ElementNotFound, lambda: Blah('test').href)
    
    def test_delete_already_deleted_host(self):
        #Verify a stale href that was deleted gives expected error
        Host.create('tyler', '1.1.1.1')
        host = Host('tyler').href
        Host('tyler').delete()
        result = SMCRequest(href=host).delete()
        self.assertIsNotNone(result.msg)
    
    def test_update_no_etag(self):
        #Failed PUT request
        Host.create('tyler', '1.1.1.1') 
        a = Host('tyler')
        element = a.describe()
        element.update(name='newtyler')
        result = SMCRequest(href=a.href, json=element).update()
        self.assertIsNotNone(result.msg)
        Host('tyler').delete()
    
    def bad_json_POST(self):
        #If customized json is going through and it's invalid, TypeError is thrown
        href = search.element_entry_point('host')
        self.assertRaises(TypeError, lambda: SMCRequest(href=href, json={'ertrte'}).create())
    
    def test_unknown_host(self):
        host = Host('blahblahblah')
        self.assertRaises(ElementNotFound, lambda: host.href)
    
    def test_export_element(self):
        #Test exporting a non-system element, should just return href
        result = Host.create('api-export-test', '2.3.4.5')
        self.assertTrue(result.href.startswith('http'))
        host = Host('api-export-test')
        export = next(host.export())
        self.assertTrue(export.startswith('http'))
        host.delete()
    
    def test_export_system_element(self):
        #Will return empty list, cannot export system elements
        host = Host('Localhost')
        export = host.export()
        self.assertIsInstance(export, list)
        self.assertTrue(len(export) == 0)
        # Now we have a task
        tasks = search.element_entry_point('task_progress')
        task = search.element_by_href_as_json(tasks)
        if task:
            for x in TaskMonitor(task[0].get('href')).watch():
                self.assertTrue(x is not None)
                print(x)
        # Test break TaskDownload, invalid directory
        task_details = search.element_by_href_as_json(task[0].get('href'))
        for link in task_details.get('link'):
            if link.get('rel') == 'result':
                #Invalid directory specification
                self.assertRaises(TaskRunFailed, lambda: TaskDownload(link.get('href'), '//////').run())
                
    
    def test_modify_system_element(self):
        #System elements should not be able to be modified
        host = Host('Localhost')
        result = host.modify_attribute(name='myLocalhost')
        self.assertIsInstance(result, SMCResult)
        self.assertRegexpMatches(result.msg, r'^Cannot modify system element')
    
    def test_modify_non_system_element(self):
        #Non system elements can be modified
        result = Host.create('api-test', '2.3.4.5')
        self.assertTrue(result.href.startswith('http'))
        host = Host('api-test')
        result = host.modify_attribute(name='newapi-test')
        self.assertEqual(200, result.code)
        host = Host('newapi-test').delete()
        self.assertEqual(204, host.code)
    
    def test_user_creation(self):
        # Create admin user
        result = AdminUser.create(name='smcpython-admin', 
                                  local_admin=True, 
                                  superuser=True,
                                  enabled=True)
        self.assertEqual(201, result.code)
        admin = AdminUser('smcpython-admin')
        self.assertEqual(200, admin.enable_disable().code)
        self.assertEqual(200, admin.change_engine_password('password').code)
        self.assertIsNotNone(admin.change_password('password').msg)
        self.assertEqual(200, admin.change_password('123Password!').code)
        self.assertEqual(204, admin.delete().code)
        
    def test_api_client(self):
        # API Clients can only be exported as of 6.1.1
        # Retrieve this API Client
        client = ApiClient('smcpython')
        self.assertTrue( next(client.export()).startswith('http') )
            
    #@unittest.skip("good")
    def testHost(self):
        #Create a host and check the etag also
        result = Host.create('api-test', '2.3.4.5')
        self.assertTrue(result.href.startswith('http'))
        
        #Get Etag
        host = Host('api-test')
        self.assertIsNotNone(host.etag)
        
        self.assertEqual(host.get_attr_by_name('address'), '2.3.4.5')
        
        self.assertEqual(host.address, '2.3.4.5')
        host.address = '1.1.1.1'
        self.assertEqual(host.address, '1.1.1.1')
        self.assertEqual(host.delete().code, 204)

    def testHost_no_addresses(self):
        host = Host.create(name='mixedhost')
        self.assertIsNotNone(host.msg)
    
    def testHost_ipv4_and_ipv6(self):
        result = Host.create(name='mixedhost', ipv6_address='2001:cdba::3257:9652', address='1.1.1.1')
        self.assertTrue(result.href.startswith('http'))
        
        host = Host('mixedhost')
        self.assertEqual(host.get_attr_by_name('address'), '1.1.1.1')
        self.assertEqual(host.get_attr_by_name('ipv6_address'), '2001:cdba::3257:9652')
        self.assertEqual(host.delete().code, 204)
        
    def test_ipv6host(self):
        result = Host.create(name='mixedhost', ipv6_address='2001:cdba::3257:9652')
        self.assertTrue(result.href.startswith('http'))
        
        host = Host('mixedhost')
        self.assertEqual(host.get_attr_by_name('ipv6_address'), '2001:cdba::3257:9652')
        self.assertEqual(host.delete().code, 204)
        
    def test_ipv4_address_with_secondary_ipv6(self):
        result = Host.create(name='mixedhost', address='1.1.1.1', secondary_ip=['2001:cdba::3257:9652'])
        self.assertTrue(result.href.startswith('http'))
        
        host = Host('mixedhost')
        self.assertEqual(host.get_attr_by_name('address'), '1.1.1.1')
        self.assertIn('2001:cdba::3257:9652', host.get_attr_by_name('secondary'))
        self.assertEqual(host.delete().code, 204)

    def test_ipv6_address_with_secondary_ipv4(self):
        result = Host.create(name='mixedhost', ipv6_address='2001:cdba::3257:9652', secondary_ip=['1.1.1.1'])
        self.assertTrue(result.href.startswith('http'))
        
        host = Host('mixedhost')
        self.assertEqual(host.get_attr_by_name('ipv6_address'), '2001:cdba::3257:9652')
        self.assertIn('1.1.1.1', host.get_attr_by_name('secondary'))
        self.assertEqual(host.delete().code, 204)
    
    #@unittest.skip("good")       
    def testAddressRange(self):
        result = AddressRange.create('api-iprange', '2.3.4.5-2.3.4.6')
        self.assertTrue(result.href.startswith('http'))
        
        addr = AddressRange('api-iprange')
        self.assertEqual(addr.get_attr_by_name('ip_range'), '2.3.4.5-2.3.4.6')
        
        self.assertEqual(addr.iprange, '2.3.4.5-2.3.4.6')
        addr.iprange = '1.1.1.1-1.1.1.2'
        self.assertEqual(addr.iprange, '1.1.1.1-1.1.1.2')
        self.assertEqual(addr.delete().code, 204)
    
    #@unittest.skip("good")    
    def testRouter(self):
        try:
            Router('foorouter').delete()
        except ElementNotFound:
            pass
        result = Router.create('foorouter', '11.1.1.1')
        self.assertTrue(result.href.startswith('http'))
        router = Router('foorouter')
        self.assertEqual(router.describe().get('address'), '11.1.1.1')
        d = SMCRequest(href=router.href).delete()
        self.assertEqual(204, d.code)
        
    def test_router_ipv4_address_with_secondary_ipv6(self):
        result = Router.create(name='mixedhost', address='1.1.1.1', secondary_ip=['2001:cdba::3257:9652'])
        self.assertTrue(result.href.startswith('http'))
        
        router = Router('mixedhost')
        self.assertEqual(router.get_attr_by_name('address'), '1.1.1.1')
        self.assertIn('2001:cdba::3257:9652', router.get_attr_by_name('secondary'))
        self.assertEqual(router.delete().code, 204)
        
    def test_router_ipv6_address_with_secondary_ipv4(self):
        result = Router.create(name='mixedhost', ipv6_address='2001:cdba::3257:9652', secondary_ip=['1.1.1.1'])
        self.assertTrue(result.href.startswith('http'))
        
        router = Router('mixedhost')
        self.assertEqual(router.get_attr_by_name('ipv6_address'), '2001:cdba::3257:9652')
        self.assertIn('1.1.1.1', router.get_attr_by_name('secondary'))
        self.assertEqual(router.delete().code, 204)
            
    #@unittest.skip("good")
    def testNetwork(self):
        # Invalid host bits
        result = Network.create('foonetwork', '12.1.1.1/24', 'comment')
        self.assertIsNotNone(result.msg)

        result = Network.create('foonetwork', '12.1.1.0/24')
        self.assertTrue(result.href.startswith('http'))
        
        network = Network('foonetwork')
        self.assertEqual(network.get_attr_by_name('ipv4_network'), '12.1.1.0/24')
        self.assertEqual(network.delete().code, 204)
    
        # Not CIDR format
        result = Network.create('foonetwork', '12.1.1.0/255.255.255.0')
        self.assertIsNotNone(result.msg)
        
    def test_network_ipv6(self):
        network = Network.create(name='mixednetwork', ipv6_network='fc00::/7')
        self.assertTrue(network.href.startswith('http'))
        
        network = Network('mixednetwork')
        self.assertEqual(network.get_attr_by_name('ipv6_network'), 'fc00::/7')
        self.assertEqual(network.delete().code, 204)
        
    def test_network_ipv6_and_ipv4(self):
        network = Network.create(name='mixednetwork', ipv4_network='12.12.12.0/24', 
                                 ipv6_network='fc00::/7')
        self.assertTrue(network.href.startswith('http'))
        
        network = Network('mixednetwork')
        self.assertEqual(network.get_attr_by_name('ipv6_network'), 'fc00::/7')
        self.assertEqual(network.get_attr_by_name('ipv4_network'), '12.12.12.0/24')
        self.assertEqual(network.delete().code, 204)
          
    #@unittest.skip("good")         
    def testGroup(self):
        # Member not href
        result = Group.create('foogroup', ['test'], 'comment')
        self.assertEqual(result.code, 400)
        
        # Same as above
        result = Group.create('foogroup', ['172.18.1.80'])
        self.assertEqual(400, result.code)
        
        # Empty group
        group = Group.create('foogroup')
        self.assertTrue(group.href.startswith('http'))
        
        # Get context
        group = Group('foogroup')
        
        # Add member
        Host.create('groupmember', '1.1.1.1')
        self.assertIn(group.update_members(members=[Host('groupmember').href]).code, [200,204])
        # Get the members back and verify
        self.assertIn(Host('groupmember').href, group.obtain_members())
        # Delete all members
        group.empty_members()
        self.assertTrue(len(group.obtain_members()) == 0)
        # Delete
        self.assertIn(group.delete().code, [200, 204])
        
    def testLocation(self):
        for locations in describe_location():
            if locations.name == 'api-location':
                self.assertEqual(locations.delete().code, 204)
    
        if session.api_version <= 6.0:
            self.assertRaises(UnsupportedEntryPoint, lambda: Location.create('api-location'))
        else:
            result = Location.create('api-location')
            self.assertTrue(result.href.startswith('http'))
            
            try:
                loc = Location('api-location')
                loc.href #ElementNotFound raised on SMC API 6.1, Location is not searchable
            except ElementNotFound:
                pass
            else:
                d = SMCRequest(result.href).delete()
                self.assertEqual(204, d.code)
        
    #@unittest.skip("good")
    def testZone(self):
        
        result = Zone.create('api-zone')
        self.assertTrue(result.href.startswith('http'))
        self.assertEqual(Zone('api-zone').delete().code, 204)
        
    #@unittest.skip("good")
    def testLogicalInterface(self):
    
        result = LogicalInterface.create('api-logical-interface')
        self.assertTrue(result.href.startswith('http'))
        r = LogicalInterface('api-logical-interface')
        self.assertEqual(r.get_attr_by_name('name'), 'api-logical-interface')
        self.assertEqual(r.delete().code, 204)

    #@unittest.skip("good")
    def testDomainName(self):
        result = DomainName.create('www.lepages.net')
        self.assertTrue(result.href.startswith('http'))  
        dn = DomainName('www.lepages.net')
        self.assertEqual(dn.get_attr_by_name('name'), 'www.lepages.net')
        self.assertEqual(dn.delete().code, 204)
    
    def testMacAddress(self):
        result = MacAddress.create(name='mymac', mac_address='22:22:22:22:22:22')
        self.assertEqual(201, result.code)
        obj = MacAddress('mymac')
        self.assertEqual(obj.get_attr_by_name('address'), '22:22:22:22:22:22')
        self.assertEqual(obj.delete().code, 204)
        
    def testContactAddress(self):
        result = prepare_contact_address(address='1.1.1.1', location='smcpython')
        self.assertIsInstance(result.get('contact_addresses'), list)
        data = result.get('contact_addresses')[0]
    
        self.assertEqual(data.get('address'), '1.1.1.1')
        self.assertTrue(data.get('location_ref').startswith('http'))
        
    def test_prepareblacklist(self):
        result = prepare_blacklist('1.1.1.1/32', '0.0.0.0/0')
        self.assertIsInstance(result, dict)
        self.assertEqual(result.get('end_point1').get('ip_network'), '1.1.1.1/32')
        self.assertEqual(result.get('end_point2').get('ip_network'), '0.0.0.0/0')
    
    #@unittest.skip("good")
    def test_Expression(self):
        #Test creating an expression
        
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
        self.assertEqual(201, expression.code)
        expr = Expression('pythonexpression')
        d = expr.delete()
        self.assertEqual(204, d.code)
        self.assertEqual(204, host9.delete().code)
        self.assertEqual(204, host10.delete().code)    
                    
    #@unittest.skip("good")
    def testTCPService(self):
        
        result = TCPService.create('api-tcpservice', 5000, 5005, comment='blahcomment')
        self.assertTrue(result.href.startswith('http'))
        
        service = TCPService('api-tcpservice')
        self.assertEqual(service.get_attr_by_name('min_dst_port'), 5000)
        self.assertEqual(service.get_attr_by_name('max_dst_port'), 5005)
        self.assertEqual(service.delete().code, 204)
    
        result = TCPService('HTTP')
        self.assertIsInstance(result.protocol_agent, Protocol)
    
    #@unittest.skip("good")
    def testUDPService(self):
        
        result = UDPService.create('api-udpservice', 5000, 5005, comment='blahcomment')
        self.assertTrue(result.href.startswith('http'))
        
        service = UDPService('api-udpservice')
        self.assertEqual(service.get_attr_by_name('min_dst_port'), 5000)
        self.assertEqual(service.get_attr_by_name('max_dst_port'), 5005)
        self.assertEqual(service.get_attr_by_name('comment'), 'blahcomment')
        
        self.assertEqual(service.delete().code, 204)
        
    #@unittest.skip("good")
    def testICMPService(self):
        
        result = ICMPService.create('api-icmp', 3)
        self.assertTrue(result.href.startswith('http'))
        
        service = ICMPService('api-icmp')
        self.assertEqual(service.get_attr_by_name('icmp_type'), 3)
        self.assertEqual(service.delete().code, 204)
        
        result = ICMPService.create('api-icmp', 3, 7, comment='api comment')
        self.assertTrue(result.href.startswith('http'))
        
        service = ICMPService('api-icmp')
        self.assertEqual(service.get_attr_by_name('icmp_type'), 3)
        self.assertEqual(service.get_attr_by_name('icmp_code'), 7)
        self.assertEqual(service.get_attr_by_name('comment'), 'api comment')
        self.assertEqual(service.delete().code, 204)
        
    #@unittest.skip("good")
    def testIPService(self):
       
        result = IPService.create('api-ipservice', 93)
        self.assertTrue(result.href.startswith('http'))
        
        service = IPService('api-ipservice')
        self.assertEqual(service.get_attr_by_name('protocol_number'), '93')
        self.assertEqual(service.delete().code, 204)
        
    #@unittest.skip("good")
    def test_ICMPv6Service(self):
        
        result = ICMPIPv6Service.create('api-Neighbor Advertisement Message', 139, comment='api-test')
        self.assertTrue(result.href.startswith('http'))
        
        service = ICMPIPv6Service('api-Neighbor Advertisement Message')
        self.assertEqual(service.get_attr_by_name('icmp_type'), 139)
        self.assertEqual(service.get_attr_by_name('comment'), 'api-test')
        
        self.assertEqual(service.delete().code, 204)
        
    def testEthernetService(self):
        pass
                 
    #@unittest.skip("good")
    def testServiceGroup(self):
        """ Test service group creation """
        result = TCPService.create('api-tcp', 5000)
        self.assertTrue(result.href.startswith('http'))
        
        result = UDPService.create('api-udp', 5001)
        self.assertTrue(result.href.startswith('http'))
      
        tcp = TCPService('api-tcp')
        udp = UDPService('api-udp')
        result = ServiceGroup.create('api-servicegroup', element=[tcp.href, udp.href], comment='test')
        self.assertTrue(result.href.startswith('http'))
        
        group = ServiceGroup('api-servicegroup')
        # Href in service group
        self.assertIn(tcp.href, group.get_attr_by_name('element'))
        self.assertIn(udp.href, group.get_attr_by_name('element'))
        
        self.assertEqual(group.delete().code, 204)
        self.assertEqual(tcp.delete().code, 204)
        self.assertEqual(udp.delete().code, 204)
        
    #@unittest.skip("good")
    def testTCPServiceGroup(self):
        
        tcp = TCPService.create('api-tcp', 5000)
        self.assertTrue(tcp.href.startswith('http'))
        
        tcp2 = TCPService.create('api-tcp2', 5001)
        self.assertTrue(tcp2.href.startswith('http'))
        
        tcp = TCPService('api-tcp')
        tcp2 = TCPService('api-tcp2')
        
        result = TCPServiceGroup.create('api-tcpservicegroup', element=[tcp.href, tcp2.href])
        self.assertTrue(result.href.startswith('http'))
        
        group = TCPServiceGroup('api-tcpservicegroup')
        self.assertIn(tcp.href, group.get_attr_by_name('element'))
        self.assertIn(tcp2.href, group.get_attr_by_name('element'))
        
        self.assertEqual(group.delete().code, 204)
        self.assertEqual(tcp.delete().code, 204)
        self.assertEqual(tcp2.delete().code, 204)
            
    def testUDPServiceGroup(self):
       
        result = UDPService.create('udp-svc1', 5000)
        self.assertTrue(result.href.startswith('http'))
        
        result = UDPService.create('udp-svc2', 5001)
        self.assertTrue(result.href.startswith('http'))
        
        udp = UDPService('udp-svc1')
        udp2 = UDPService('udp-svc2') 
        result = UDPServiceGroup.create('api-udpservicegroup', element=[udp.href, udp2.href])
        self.assertTrue(result.href.startswith('http'))
        
        group = UDPServiceGroup('api-udpservicegroup')
        self.assertIn(udp.href, group.get_attr_by_name('element'))
        self.assertIn(udp2.href, group.get_attr_by_name('element'))
        
        self.assertEqual(group.delete().code, 204)
        self.assertEqual(udp.delete().code, 204)
        self.assertEqual(udp2.delete().code, 204)
        
        
    def testIPServiceGroup(self):
       
        result = IPService.create('api-service', 93)
        self.assertTrue(result.href.startswith('http'))
        
        result = IPService.create('api-service2', 90)
        self.assertTrue(result.href.startswith('http'))
        
        ipsvc = IPService('api-service')
        ipsvc2 = IPService('api-service2')
        
        result = IPServiceGroup.create('api-ipservicegroup', element=[ipsvc.href, ipsvc2.href], comment='mygroup')
        self.assertTrue(result.href.startswith('http'))
        
        group = IPServiceGroup('api-ipservicegroup')
        self.assertIn(ipsvc.href, group.get_attr_by_name('element'))
        self.assertIn(ipsvc2.href, group.get_attr_by_name('element'))
        
        self.assertEqual(group.delete().code, 204)
        self.assertEqual(ipsvc.delete().code, 204)
        self.assertEqual(ipsvc2.delete().code, 204)
    
    def test_IPList_createWithJson(self):
        if session.api_version >= 6.1:
            try:
                iplist = IPList('smcpython-iplist')
                self.assertEqual(iplist.delete().code, 204)
            except ElementNotFound:
                pass
            
            ips = ['1.1.1.1', '2.2.2.2']
            ip = IPList.create(name='smcpython-iplist', iplist=ips)
            self.assertEqual(ip.code, 202)
    
    def test_download_IPList_as_text(self):
        if session.api_version >= 6.1:
            location = describe_ip_list(name=['smcpython-iplist'])
            if location:
                iplist = location[0]
                result = iplist.download(filename='iplist.txt', as_type='txt')
                self.assertEqual(200, result.code)
    
    def test_FAILED_download_IPList_as_text(self):
        #Fails if directory doesnt exist or is a directory
        if session.api_version >= 6.1:
            location = describe_ip_list(name=['smcpython-iplist'])
            if location:
                iplist = location[0]
                self.assertRaises(IOError, lambda: iplist.download(filename='/blah/ahagsd/iplist.txt', as_type='txt'))
                           
    def test_download_IPList_as_zip(self): 
        if session.api_version >= 6.1:
            location = describe_ip_list(name=['smcpython-iplist'])
            if location:
                iplist = location[0]
                result = iplist.download(filename='iplist.zip', as_type='zip')
                self.assertEqual(200, result.code)
                # Require the filename, will fail
                self.assertRaises(MissingRequiredInput, lambda: iplist.download(as_type='zip'))
        
    def test_download_IPList_as_json(self):
        if session.api_version >= 6.1:
            location = describe_ip_list(name=['smcpython-iplist'])
            if location:
                iplist = location[0]
                result = iplist.download(as_type='json')
                ips = ['1.1.1.1', '2.2.2.2']
                #print result.json
                self.assertEqual(ips, result.json.get('ip'))
    
    def test_upload_IPList_as_zip(self):
        if session.api_version >= 6.1:
            location = describe_ip_list(name=['smcpython-iplist'])
            if location:
                iplist = location[0]
                result = iplist.upload(filename='iplist.zip') 
                self.assertEqual(202, result.code)
            else:
                ip = IPList.create(name='smcpython-iplist')
                self.assertEqual(201, ip.code, ip.msg)
                lst = IPList('smcpython-iplist')
                result = lst.upload(filename='iplist.zip')
                self.assertEqual(202, result.code)
               
    def test_upload_IPList_as_txt(self):
        if session.api_version >= 6.1:
            import time
            time.sleep(2)
            location = describe_ip_list(name=['smcpython-iplist'])
            if location:
                iplist = location[0]
                result = iplist.upload(filename='iplist.txt', as_type='txt')
                self.assertEqual(202, result.code)
            else:
                ip = IPList.create(name='smcpython-iplist')
                self.assertEqual(201, ip.code, ip.msg)
                lst = IPList('smcpython-iplist')
                result = lst.upload(filename='iplist.txt', as_type='txt')
                self.assertEqual(202, result.code, result.msg)
                self.assertEqual(204, lst.delete().code)
                
    def test_upload_IPList_as_json(self):
        if session.api_version >= 6.1:
            location = describe_ip_list(name=['smcpython-iplist'])
            if location:
                iplist = location[0]
                result = iplist.upload(json={'ip': ['1.1.1.1', '2.2.2.2', '3.3.3.3']}, as_type='json')
                self.assertEqual(202, result.code)
        
        for iplist in describe_ip_list(name=['smcpython-iplist']):
            d = SMCRequest(iplist.href).delete()
            self.assertEqual(204, d.code)     
    
    def test_URLApplication(self):
        # URL List Application
        result = URLListApplication.create(name='whitelist', 
                                           url_entry=['www.google.com', 'www.cnn.com'])
        self.assertTrue(result.href.startswith('http'))
        self.assertIn(URLListApplication('whitelist').delete().code, [200, 204])
    
    def test_zone_helper(self):
        result = zone_helper('foozone')
        self.assertTrue(result.startswith('http'))
        d = SMCRequest(href=result).delete()
        self.assertEqual(204, d.code)
    
    def test_location_helper(self):
        result = location_helper('foolocation')
        self.assertTrue(result.startswith('http'))
        d = SMCRequest(href=result).delete()
        self.assertEqual(204, d.code)
        
    def test_logical_interface_helper(self):
        result = logical_intf_helper('foointerface')
        self.assertTrue(result.startswith('http'))
        d = SMCRequest(href=result).delete()
        self.assertEqual(204, d.code)
    
if __name__ == "__main__":
    unittest.main()
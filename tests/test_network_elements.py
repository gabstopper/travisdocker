import io
import unittest
import mock
from smc.tests.constants import url, api_key, verify, is_min_required_smc_version
from smc.administration.system import System
from smc import session
import smc.actions.search as search
from smc.elements.network import Zone, DomainName, IPList, Host, AddressRange, Router,\
    Network, Expression, URLListApplication
from smc.elements.service import UDPService, ICMPService, ICMPIPv6Service, IPService, TCPService,\
    Protocol, EthernetService
from smc.elements.group import Group, ServiceGroup, TCPServiceGroup, UDPServiceGroup, \
    IPServiceGroup
from smc.elements.other import LogicalInterface, Location, MacAddress,\
    prepare_blacklist
from smc.elements.collection import describe_ip_list, describe_location
from smc.base.model import Element
from smc.api.exceptions import UnsupportedEntryPoint, ElementNotFound,\
    MissingRequiredInput, TaskRunFailed, CreateElementFailed, ModificationFailed
from smc.api.common import SMCRequest
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
        class Blah(Element): pass
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
        self.assertTrue(result.startswith('http'))
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
                with self.assertRaises(TaskRunFailed):
                    TaskDownload(link.get('href'), '//////').run()
                
    
    def test_modify_system_element(self):
        #System elements should not be able to be modified
        host = Host('Localhost')
        with self.assertRaises(ModificationFailed):
            host.modify_attribute(name='myLocalhost')
        
    def test_modify_non_system_element(self):
        #Non system elements can be modified
        result = Host.create('api-test', '2.3.4.5')
        self.assertTrue(result.startswith('http'))
        host = Host('api-test')
        result = host.modify_attribute(name='newapi-test')
        self.assertIsNone(result)
        Host('newapi-test').delete()
        
    def test_user_creation(self):
        # Create admin user
        result = AdminUser.create(name='smcpython-admin', 
                                  local_admin=True, 
                                  superuser=True,
                                  enabled=True)
        self.assertTrue(result.startswith('http'))
        admin = AdminUser('smcpython-admin')
        self.assertIsNone(admin.enable_disable())
        self.assertIsNone(admin.change_engine_password('password'))
        with self.assertRaises(ModificationFailed):
            admin.change_password('password')
        self.assertIsNone(admin.change_password('123Password!'))
        admin.delete()
        
    def test_api_client(self):
        # API Clients can only be exported as of 6.1.1
        client = ApiClient('smcpython')
        self.assertTrue(client.href.startswith('http'))
            
    #@unittest.skip("good")
    def testHost(self):
        #Create a host and check the etag also
        result = Host.create('api-test', '2.3.4.5')
        self.assertTrue(result.startswith('http'))
        
        #Get Etag
        host = Host('api-test')
        self.assertIsNotNone(host.etag)
        
        self.assertEqual(host.attr_by_name('address'), '2.3.4.5')
        
        self.assertEqual(host.address, '2.3.4.5')
        host.address = '1.1.1.1'
        self.assertEqual(host.address, '1.1.1.1')
        host.secondary = ['8.8.8.8', '9.9.9.9']
        for ip in host.secondary:
            self.assertIn(ip, ['8.8.8.8', '9.9.9.9'])
        host.ipv6_address = '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
        self.assertEqual(host.ipv6_address, '2001:0db8:85a3:0000:0000:8a2e:0370:7334')
        host.delete()

    def testHost_no_addresses(self):
        with self.assertRaises(CreateElementFailed):
            Host.create(name='mixedhost')
        
    def testHost_ipv4_and_ipv6(self):
        result = Host.create(name='mixedhost', ipv6_address='2001:cdba::3257:9652', address='1.1.1.1')
        self.assertTrue(result.startswith('http'))
        
        host = Host('mixedhost')
        self.assertEqual(host.attr_by_name('address'), '1.1.1.1')
        self.assertEqual(host.attr_by_name('ipv6_address'), '2001:cdba::3257:9652')
        host.delete()
        
    def test_ipv6host(self):
        result = Host.create(name='mixedhost', ipv6_address='2001:cdba::3257:9652')
        self.assertTrue(result.startswith('http'))
        
        host = Host('mixedhost')
        self.assertEqual(host.attr_by_name('ipv6_address'), '2001:cdba::3257:9652')
        host.delete()
        
    def test_ipv4_address_with_secondary_ipv6(self):
        result = Host.create(name='mixedhost', address='1.1.1.1', secondary_ip=['2001:cdba::3257:9652'])
        self.assertTrue(result.startswith('http'))
        
        host = Host('mixedhost')
        self.assertEqual(host.attr_by_name('address'), '1.1.1.1')
        self.assertIn('2001:cdba::3257:9652', host.attr_by_name('secondary'))
        host.delete()

    def test_ipv6_address_with_secondary_ipv4(self):
        result = Host.create(name='mixedhost', ipv6_address='2001:cdba::3257:9652', secondary_ip=['1.1.1.1'])
        self.assertTrue(result.startswith('http'))
        
        host = Host('mixedhost')
        self.assertEqual(host.attr_by_name('ipv6_address'), '2001:cdba::3257:9652')
        self.assertIn('1.1.1.1', host.attr_by_name('secondary'))
        host.delete()
    
    #@unittest.skip("good")       
    def testAddressRange(self):
        result = AddressRange.create('api-iprange', '2.3.4.5-2.3.4.6')
        self.assertTrue(result.startswith('http'))
        
        addr = AddressRange('api-iprange')
        self.assertEqual(addr.attr_by_name('ip_range'), '2.3.4.5-2.3.4.6')
        
        self.assertEqual(addr.iprange, '2.3.4.5-2.3.4.6')
        addr.iprange = '1.1.1.1-1.1.1.2'
        self.assertEqual(addr.iprange, '1.1.1.1-1.1.1.2')
        addr.delete()
    
    #@unittest.skip("good")    
    def testRouter(self):
        try:
            Router('foorouter').delete()
        except ElementNotFound:
            pass
        result = Router.create('foorouter', '11.1.1.1')
        self.assertTrue(result.startswith('http'))
        router = Router('foorouter')
        self.assertEqual(router.data.get('address'), '11.1.1.1')
        d = SMCRequest(href=router.href).delete()
        self.assertEqual(204, d.code)
        
    def test_router_ipv4_address_with_secondary_ipv6(self):
        result = Router.create(name='mixedhost', address='1.1.1.1', 
                               secondary_ip=['2001:cdba::3257:9652'])
        self.assertTrue(result.startswith('http'))
        
        router = Router('mixedhost')
        self.assertEqual(router.attr_by_name('address'), '1.1.1.1')
        self.assertIn('2001:cdba::3257:9652', router.attr_by_name('secondary'))
        router.delete()
        
    def test_router_ipv6_address_with_secondary_ipv4(self):
        result = Router.create(name='mixedhost', 
                               ipv6_address='2001:cdba::3257:9652', 
                               secondary_ip=['1.1.1.1'])
        self.assertTrue(result.startswith('http'))
        
        router = Router('mixedhost')
        self.assertEqual(router.attr_by_name('ipv6_address'), '2001:cdba::3257:9652')
        self.assertIn('1.1.1.1', router.attr_by_name('secondary'))
        router.delete()
            
    #@unittest.skip("good")
    def testNetwork(self):
        # Invalid host bits
        with self.assertRaises(CreateElementFailed):
            Network.create('foonetwork', '12.1.1.1/24', 'comment')
        
        result = Network.create('foonetwork', '12.1.1.0/24')
        self.assertTrue(result.startswith('http'))
        
        network = Network('foonetwork')
        self.assertEqual(network.attr_by_name('ipv4_network'), '12.1.1.0/24')
        network.delete()
    
        # Not CIDR format
        with self.assertRaises(CreateElementFailed):
            Network.create('foonetwork', '12.1.1.0/255.255.255.0')
        
    def test_network_ipv6(self):
        network = Network.create(name='mixednetwork', ipv6_network='fc00::/7')
        self.assertTrue(network.startswith('http'))
        
        network = Network('mixednetwork')
        self.assertEqual(network.attr_by_name('ipv6_network'), 'fc00::/7')
        network.delete()
        
    def test_network_ipv6_and_ipv4(self):
        network = Network.create(name='mixednetwork', ipv4_network='12.12.12.0/24', 
                                 ipv6_network='fc00::/7')
        self.assertTrue(network.startswith('http'))
        
        network = Network('mixednetwork')
        self.assertEqual(network.attr_by_name('ipv6_network'), 'fc00::/7')
        self.assertEqual(network.attr_by_name('ipv4_network'), '12.12.12.0/24')
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
        self.assertTrue(group.startswith('http'))
        
        # Get context
        group = Group('foogroup')
        
        # Add member
        Host.create('groupmember', '1.1.1.1')
        self.assertIsNone(group.update_members(members=[Host('groupmember').href]))
        # Get the members back and verify
        self.assertIn(Host('groupmember').href, group.obtain_members())
        # Delete all members
        group.empty_members()
        self.assertTrue(len(group.obtain_members()) == 0)
        # Delete
        group.delete()
        
    def testLocation(self):
        for locations in describe_location():
            if locations.name == 'api-location':
                self.assertEqual(locations.delete().code, 204)
    
        if session.api_version <= 6.0:
            self.assertRaises(UnsupportedEntryPoint, lambda: Location.create('api-location'))
        else:
            result = Location.create('api-location')
            self.assertTrue(result.startswith('http'))
            
            try:
                loc = Location('api-location')
                loc.href #ElementNotFound raised on SMC API 6.1, Location is not searchable
            except ElementNotFound:
                pass
            else:
                d = SMCRequest(result).delete()
                self.assertEqual(204, d.code)
        
    #@unittest.skip("good")
    def testZone(self):
        
        result = Zone.create('api-zone')
        self.assertTrue(result.startswith('http'))
        Zone('api-zone').delete()
        
    #@unittest.skip("good")
    def testLogicalInterface(self):
    
        result = LogicalInterface.create('api-logical-interface')
        self.assertTrue(result.startswith('http'))
        r = LogicalInterface('api-logical-interface')
        self.assertEqual(r.attr_by_name('name'), 'api-logical-interface')
        r.delete()

    #@unittest.skip("good")
    def testDomainName(self):
        result = DomainName.create('www.lepages.net')
        self.assertTrue(result.startswith('http'))  
        dn = DomainName('www.lepages.net')
        self.assertEqual(dn.attr_by_name('name'), 'www.lepages.net')
        dn.delete()
    
    def testMacAddress(self):
        result = MacAddress.create(name='mymac', mac_address='22:22:22:22:22:22')
        self.assertTrue(result.startswith('http'))
        
        obj = MacAddress('mymac')
        self.assertEqual(obj.attr_by_name('address'), '22:22:22:22:22:22')
        obj.delete()
            
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
        self.assertTrue(expression.startswith('http'))
        expr = Expression('pythonexpression')
        expr.delete()
        host9.delete()
        host10.delete()  
                    
    #@unittest.skip("good")
    def testTCPService(self):
        
        result = TCPService.create('api-tcpservice', 5000, 5005, comment='blahcomment')
        self.assertTrue(result.startswith('http'))
        
        service = TCPService('api-tcpservice')
        self.assertEqual(service.attr_by_name('min_dst_port'), 5000)
        self.assertEqual(service.attr_by_name('max_dst_port'), 5005)
        service.delete()
    
        result = TCPService('HTTP')
        self.assertIsInstance(result.protocol_agent, Protocol)
    
    #@unittest.skip("good")
    def testUDPService(self):
        
        result = UDPService.create('api-udpservice', 5000, 5005, comment='blahcomment')
        self.assertTrue(result.startswith('http'))
        
        service = UDPService('api-udpservice')
        self.assertEqual(service.attr_by_name('min_dst_port'), 5000)
        self.assertEqual(service.attr_by_name('max_dst_port'), 5005)
        self.assertEqual(service.attr_by_name('comment'), 'blahcomment')
        
        service.delete()
        
    #@unittest.skip("good")
    def testICMPService(self):
        
        result = ICMPService.create('api-icmp', 3)
        self.assertTrue(result.startswith('http'))
        
        service = ICMPService('api-icmp')
        self.assertEqual(service.attr_by_name('icmp_type'), 3)
        service.delete()
        
        result = ICMPService.create('api-icmp', 3, 7, comment='api comment')
        self.assertTrue(result.startswith('http'))
        
        service = ICMPService('api-icmp')
        self.assertEqual(service.attr_by_name('icmp_type'), 3)
        self.assertEqual(service.attr_by_name('icmp_code'), 7)
        self.assertEqual(service.attr_by_name('comment'), 'api comment')
        service.delete()
        
    #@unittest.skip("good")
    def testIPService(self):
       
        result = IPService.create('api-ipservice', 93)
        self.assertTrue(result.startswith('http'))
        
        service = IPService('api-ipservice')
        self.assertEqual(service.attr_by_name('protocol_number'), '93')
        service.delete()
        
    #@unittest.skip("good")
    def test_ICMPv6Service(self):
        
        result = ICMPIPv6Service.create('api-Neighbor Advertisement Message', 139, 
                                        comment='api-test')
        self.assertTrue(result.startswith('http'))
        
        service = ICMPIPv6Service('api-Neighbor Advertisement Message')
        self.assertEqual(service.attr_by_name('icmp_type'), 139)
        self.assertEqual(service.attr_by_name('comment'), 'api-test')
        
        service.delete()
        
    def testEthernetService(self):
        system = System()
        if is_min_required_smc_version(system.smc_version, '6.1.2'):
            result = EthernetService.create(name='myService', 
                                            ethertype='32828')
            self.assertTrue(result.startswith('http'))
            EthernetService('myService').delete()
                 
    #@unittest.skip("good")
    def testServiceGroup(self):
        """ Test service group creation """
        result = TCPService.create('api-tcp', 5000)
        self.assertTrue(result.startswith('http'))
        
        result = UDPService.create('api-udp', 5001)
        self.assertTrue(result.startswith('http'))
      
        tcp = TCPService('api-tcp')
        udp = UDPService('api-udp')
        result = ServiceGroup.create('api-servicegroup', 
                                     element=[tcp.href, udp.href], 
                                     comment='test')
        self.assertTrue(result.startswith('http'))
        
        group = ServiceGroup('api-servicegroup')
        # Href in service group
        self.assertIn(tcp.href, group.attr_by_name('element'))
        self.assertIn(udp.href, group.attr_by_name('element'))
        
        group.delete()
        tcp.delete()
        udp.delete()
        
    #@unittest.skip("good")
    def testTCPServiceGroup(self):
        
        tcp = TCPService.create('api-tcp', 5000)
        self.assertTrue(tcp.startswith('http'))
        
        tcp2 = TCPService.create('api-tcp2', 5001)
        self.assertTrue(tcp2.startswith('http'))
        
        tcp = TCPService('api-tcp')
        tcp2 = TCPService('api-tcp2')
        
        result = TCPServiceGroup.create('api-tcpservicegroup', 
                                        element=[tcp.href, tcp2.href])
        self.assertTrue(result.startswith('http'))
        
        group = TCPServiceGroup('api-tcpservicegroup')
        self.assertIn(tcp.href, group.attr_by_name('element'))
        self.assertIn(tcp2.href, group.attr_by_name('element'))
        
        group.delete()
        tcp.delete()
        tcp2.delete()
            
    def testUDPServiceGroup(self):
       
        result = UDPService.create('udp-svc1', 5000)
        self.assertTrue(result.startswith('http'))
        
        result = UDPService.create('udp-svc2', 5001)
        self.assertTrue(result.startswith('http'))
        
        udp = UDPService('udp-svc1')
        udp2 = UDPService('udp-svc2') 
        result = UDPServiceGroup.create('api-udpservicegroup', 
                                        element=[udp.href, udp2.href])
        self.assertTrue(result.startswith('http'))
        
        group = UDPServiceGroup('api-udpservicegroup')
        self.assertIn(udp.href, group.attr_by_name('element'))
        self.assertIn(udp2.href, group.attr_by_name('element'))
        
        group.delete()
        udp.delete()
        udp2.delete()
            
    def testIPServiceGroup(self):
       
        result = IPService.create('api-service', 93)
        self.assertTrue(result.startswith('http'))
        
        result = IPService.create('api-service2', 90)
        self.assertTrue(result.startswith('http'))
        
        ipsvc = IPService('api-service')
        ipsvc2 = IPService('api-service2')
        
        result = IPServiceGroup.create('api-ipservicegroup', 
                                       element=[ipsvc.href, ipsvc2.href], 
                                       comment='mygroup')
        self.assertTrue(result.startswith('http'))
        
        group = IPServiceGroup('api-ipservicegroup')
        self.assertIn(ipsvc.href, group.attr_by_name('element'))
        self.assertIn(ipsvc2.href, group.attr_by_name('element'))
        
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
            self.assertTrue(ip.startswith('http'))
    
    def test_download_IPList_as_text(self):
        if session.api_version >= 6.1:
            location = describe_ip_list(name=['smcpython-iplist'])
            if location:
                iplist = location[0]
                result = iplist.download(filename='iplist.txt', as_type='txt')
                self.assertIsNone(result)
    
    def test_FAILED_download_IPList_as_text(self):
        #Fails if directory doesnt exist or is a directory
        if session.api_version >= 6.1:
            location = describe_ip_list(name=['smcpython-iplist'])
            if location:
                iplist = location[0]
                with self.assertRaises(IOError):
                    iplist.download(filename='/blah/ahagsd/iplist.txt', 
                                    as_type='txt')
                     
    def test_download_IPList_as_zip(self): 
        if session.api_version >= 6.1:
            location = describe_ip_list(name=['smcpython-iplist'])
            if location:
                iplist = location[0]
                result = iplist.download(filename='iplist.zip', as_type='zip')
                self.assertIsNone(result)
                # Require the filename, will fail
                with self.assertRaises(MissingRequiredInput):
                    iplist.download(as_type='zip')
        
    def test_download_IPList_as_json(self):
        system = System()
        
        if session.api_version >= 6.1:
            location = describe_ip_list(name=['smcpython-iplist'])
            if location:
                iplist = location[0]
                result = iplist.download(as_type='json')
                # Version 6.1.2 has a problem when JSON is NOT returned when
                # specifying application/json headers
                if is_min_required_smc_version(system.smc_version, '6.1.2'):
                    self.assertIsNone(result)
                else:
                    ips = ['1.1.1.1', '2.2.2.2']
                    self.assertEqual(ips, result.json.get('ip'))
    
    #@mock.patch('smc.elements.network.open', create=True)      
    def test_upload_IPList_as_zip(self):
        if session.api_version >= 6.1:
            
            #zf = zipfile.ZipFile(io.BytesIO(), "a", zipfile.ZIP_DEFLATED, False)
            # Write the file to the in-memory zip
            #zf.writestr('ip_addresses', '1.1.1.1\n2.2.2.2\n3.3.3.3')
            #print(zf)
            
            #mock_open.return_value = ('iplist.zip', zf)
            iplist = None
            location = describe_ip_list(name=['smcpython-iplist'])
            if location:
                iplist = location[0]
            else:
                href = IPList.create(name='smcpython-iplist')
                self.assertTrue(href.startswith('http'))
                iplist = IPList('smcpython-iplist')
                
            result = iplist.upload(filename='iplist.zip')
            self.assertIsNone(result)
       
    @mock.patch('smc.elements.network.open', create=True)           
    def test_upload_IPList_as_txt(self, mock_open):
        if session.api_version >= 6.1:
            cfg = ("1.1.1.1\n2.2.2.2")
            mock_open.return_value = io.StringIO(u'{}'.format(cfg))
            iplist = None
            location = describe_ip_list(name=['smcpython-iplist'])
            if location:
                iplist = location[0]
            else:
                href = IPList.create(name='smcpython-iplist')
                self.assertTrue(href.startswith('http'))
                iplist = IPList('smcpython-iplist')
                
            result = iplist.upload(filename='iplist.txt', as_type='txt')
            self.assertIsNone(result)
            iplist.delete()
                
              
    def test_upload_IPList_as_json(self):
        if session.api_version >= 6.1:
            location = describe_ip_list(name=['smcpython-iplist'])
            if location:
                iplist = location[0]
                result = iplist.upload(json={'ip': ['1.1.1.1', '2.2.2.2', '3.3.3.3']}, 
                                       as_type='json')
                self.assertIsNone(result)
                
                with self.assertRaises(CreateElementFailed):
                    iplist.upload(json={'ip': ['1.1.1.1a']}, 
                                       as_type='json')
        
        for iplist in describe_ip_list(name=['smcpython-iplist']):
            d = SMCRequest(iplist.href).delete()
            self.assertEqual(204, d.code)
    
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
        result = URLListApplication.create(name='whitelist', 
                                           url_entry=['www.google.com', 'www.cnn.com'])
        self.assertTrue(result.startswith('http'))
        URLListApplication('whitelist').delete()
    
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
'''
Created on Oct 30, 2016

@author: davidlepage
'''
import unittest
from smc import session
from .constants import url, api_key, verify
from smc.routing.access_list import IPAccessList, IPv6AccessList
from smc.routing.prefix_list import IPPrefixList, IPv6PrefixList
from smc.api.common import SMCRequest

class Test(unittest.TestCase):

    def setUp(self):
        session.login(url=url, api_key=api_key, verify=verify)
            
    def tearDown(self):
        try:
            session.logout()
        except SystemExit:
            pass
        
    def test_ip_access_list(self):
        alist = IPAccessList.create(name='smcpython-acl', entries=[('1.1.1.0/24', 'permit')])
        self.assertEqual(201, alist.code)
        
        acllist = IPAccessList('smcpython-acl')
        a = acllist.add_entry('12.12.12.12/32', 'permit')
        self.assertEqual(200, a.code)
        self.assertTrue(len(acllist.view()) >= 1)
        
        b = acllist.remove_entry('12.12.12.12/32')
        self.assertEqual(200, b.code)
        #test describe
        
        c = SMCRequest(href=acllist.href).delete()
        self.assertEqual(204, c.code)
    
    def test_ipv6_access_list(self):
        
        acl = IPv6AccessList.create(name='smcpython-ipv6acl',
                                    entries=[('2001:db8:1::1/128', 'permit')])
        self.assertEqual(201, acl.code)
        
        acl = IPv6AccessList('smcpython-ipv6acl')
        
        a = acl.add_entry('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128', 'deny')
        self.assertEqual(200, a.code)
        self.assertTrue(len(acl.view()) >= 1)
        
        b = acl.remove_entry('2001:db8:1::1/128')
        self.assertEqual(200, b.code)
        
        c = SMCRequest(href=acl.href).delete()
        self.assertEqual(204, c.code)

    def test_ip_prefix_list(self):
        
        prefix = IPPrefixList.create(name='smcpython-prefix',
                                     entries=[('10.0.0.0/8', 16, 32, 'deny'),
                                              ('192.16.1.0/24', 25, 32, 'permit')])
        self.assertEqual(201, prefix.code)
        
        prefix = IPPrefixList('smcpython-prefix')
        
        a = prefix.add_entry('192.168.3.0/24', 25, 26, 'deny')
        self.assertEqual(200, a.code)
        self.assertTrue(len(prefix.view()) >= 1)
        
        b = prefix.remove_entry('192.168.3.0/24')
        self.assertEqual(200, b.code)
        
        c = SMCRequest(href=prefix.href).delete()
        self.assertEqual(204, c.code)
    
    def test_ipv6_prefix_list(self):

        prefix = IPv6PrefixList.create(name='smcpython-v6prefix', 
                                       entries=[('ab00::/64', 65, 128, 'deny')])
        self.assertEqual(201, prefix.code)
        
        prefix6 = IPv6PrefixList('smcpython-v6prefix')
        
        a = prefix6.add_entry('AB40::1/64', 65, 128, 'permit')
        self.assertEqual(200, a.code)
        self.assertTrue(len(prefix6.view()) >= 1)
        
        b = prefix6.remove_entry('ab40::1/64')
        self.assertEqual(200, b.code)
        
        c = SMCRequest(href=prefix6.href).delete()
        self.assertEqual(204, c.code)
        
        
if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
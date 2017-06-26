'''
Created on Oct 30, 2016

@author: davidlepage
'''
import unittest
from smc import session
from smc.tests.constants import url, api_key, verify
from smc.routing.access_list import IPAccessList, IPv6AccessList
from smc.routing.prefix_list import IPPrefixList, IPv6PrefixList
from smc.api.exceptions import UpdateElementFailed


class Test(unittest.TestCase):

    def setUp(self):
        session.login(url=url, api_key=api_key, verify=verify)

    def tearDown(self):
        try:
            session.logout()
        except SystemExit:
            pass

    def test_ip_access_list(self):
        alist = IPAccessList.create(
            name='smcpython-acl', entries=[('1.1.1.0/24', 'permit')])
        self.assertTrue(alist.href.startswith('http'))

        acllist = IPAccessList('smcpython-acl')
        a = acllist.add_entry('12.12.12.12/32', 'permit')
        self.assertIsNone(a)
        self.assertTrue(len(acllist.view()) >= 1)

        with self.assertRaises(UpdateElementFailed):
            acllist.add_entry('12.12.12.12a', 'permit')

        b = acllist.remove_entry('12.12.12.12/32')
        self.assertIsNone(b)
        # test describe

        acllist.delete()

    def test_ipv6_access_list(self):

        acl = IPv6AccessList.create(name='smcpython-ipv6acl',
                                    entries=[('2001:db8:1::1/128', 'permit')])
        self.assertTrue(acl.href.startswith('http'))

        acl = IPv6AccessList('smcpython-ipv6acl')

        a = acl.add_entry(
            'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128', 'deny')
        self.assertIsNone(a)

        self.assertTrue(len(acl.view()) >= 1)

        b = acl.remove_entry('2001:db8:1::1/128')
        self.assertIsNone(b)

        acl.delete()

    def test_ip_prefix_list(self):

        prefix = IPPrefixList.create(name='smcpython-prefix',
                                     entries=[('10.0.0.0/8', 16, 32, 'deny'),
                                              ('192.16.1.0/24', 25, 32, 'permit')])
        self.assertTrue(prefix.href.startswith('http'))

        prefix = IPPrefixList('smcpython-prefix')

        a = prefix.add_entry('192.168.3.0/24', 25, 26, 'deny')
        self.assertIsNone(a)
        self.assertTrue(len(prefix.view()) >= 1)

        b = prefix.remove_entry('192.168.3.0/24')
        self.assertIsNone(b)

        prefix.delete()

    def test_ipv6_prefix_list(self):

        prefix = IPv6PrefixList.create(name='smcpython-v6prefix',
                                       entries=[('ab00::/64', 65, 128, 'deny')])
        self.assertTrue(prefix.href.startswith('http'))

        prefix6 = IPv6PrefixList('smcpython-v6prefix')

        a = prefix6.add_entry('AB40::1/64', 65, 128, 'permit')
        self.assertIsNone(a)
        self.assertTrue(len(prefix6.view()) >= 1)

        with self.assertRaises(UpdateElementFailed):
            prefix6.add_entry('123456', 65, 128, 'permit')

        b = prefix6.remove_entry('ab40::1/64')
        self.assertIsNone(b)

        prefix6.delete()


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()

'''
Created on Dec 1, 2016

@author: davidlepage
'''
from smc import session

import unittest
from constants import url, api_key, verify
from smc import session
from smc.elements.network import Host
from smc.api.exceptions import ElementNotFound, SMCConnectionError

class Test(unittest.TestCase):
       
    def setUp(self):
        print("-------Called setup-------")
        session.login(url=url, api_key=api_key, verify=verify)
       
    def tearDown(self):
        print("-------Called tear down-------")
        session.logout()
    
    def test_connect(self):
        host = Host('blah')
        self.assertRaises(ElementNotFound, lambda: host.href)
        

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
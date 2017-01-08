'''
Created on Dec 1, 2016

@author: davidlepage
'''
from smc import session

import time
import unittest
from smc import session
from smc.elements.network import Host
from smc.api.exceptions import ElementNotFound

class Test(unittest.TestCase):
       
    print("Running Search Test..")
    time.sleep(5)
    def setUp(self):
        print("-------Called setup-------")
        session.login(url='http://172.32.0.10:8082', api_key='kKphtsbQKjjfHR7amodA0001', timeout=45)
        print("Here")
    
    def tearDown(self):
        print("-------Called tear down-------")
        session.logout()
    
    def test_connect(self):
        host = Host('blah')
        self.assertRaises(ElementNotFound, lambda: host.href)
        

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
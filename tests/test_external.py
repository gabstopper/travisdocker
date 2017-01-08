'''
Created on Dec 1, 2016

@author: davidlepage
'''
from smc import session

import time
import unittest
from smc import session
from smc.elements.network import Host
from smc.api.exceptions import ElementNotFound, SMCConnectionError

class Test(unittest.TestCase):
       
    print("Running Search Test..")
    def setUp(self):
        print("-------Called setup-------")
        for _ in range (1, 5):
            try:
                session.login(url='http://127.0.0.1:8082', api_key='kKphtsbQKjjfHR7amodA0001', timeout=30)
                break
            except SMCConnectionError as e:
                print("Timed out, pausing then will try again: %s" % e)
                time.sleep(5)
        print("Dropped out bottom")
    
    def tearDown(self):
        print("-------Called tear down-------")
        session.logout()
    
    def test_connect(self):
        host = Host('blah')
        self.assertRaises(ElementNotFound, lambda: host.href)
        

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
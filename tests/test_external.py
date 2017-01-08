'''
Created on Dec 1, 2016

@author: davidlepage
'''
from smc import session

import unittest
from smc import session

class Test(unittest.TestCase):
       
    print("Running Search Test..")
    def setUp(self):
        print("-------Called setup-------")
        session.login(url='http://172.18.1.26:8082', api_key='kKphtsbQKjjfHR7amodA0001', timeout=45)
        print("Here")
    
    def tearDown(self):
        print("-------Called tear down-------")
        session.logout()


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
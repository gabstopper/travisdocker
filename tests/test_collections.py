'''
Created on Aug 24, 2016

@author: davidlepage
'''

import unittest
import inspect
from .constants import url, api_key, verify
from smc import session
import smc.elements.collection
from smc.elements.network import Host
from smc.elements.collection import describe_host
from smc.api.common import SMCRequest


class Test(unittest.TestCase):

    tmp = {}
    def setUp(self):
        #session.login(url='http://172.18.1.150:8082', api_key='EiGpKD4QxlLJ25dbBEp20001')
        session.login(url=url, api_key=api_key, timeout=45, verify=verify)
    def tearDown(self):
        try:
            session.logout()
        except SystemExit:
            pass
    
    def testDescribe(self):
        all_functions = inspect.getmembers(smc.elements.collection, inspect.isfunction)
        for func in all_functions:
            if func[0].startswith('describe'):
                print("Calling: {}".format(func[0]))
                f = getattr(smc.elements.collection, func[0])
                result = f()
                print(len(result), result)        
            #result = getattr(obj, "method")(args)
    
    def test_host_by_name(self):
        Host.create('smcpython-tmp', '1.1.1.1')
        for x in describe_host(name=['smcpython-tmp']):
            self.assertIsNotNone(x.href)
            self.assertIsNotNone(x.name)
            d = SMCRequest(x.href).delete()
            self.assertEqual(204, d.code)
            
    def test_host_by_str(self):
        Host.create('smcpython-tmp', '1.1.1.1')
        for x in describe_host(name='smcpython-tmp'):
            self.assertIsNotNone(x.href)
            self.assertIsNotNone(x.name)
            host = Host('smcpython-tmp')
            self.assertEqual(204, host.delete().code)
            
    def test_host_by_str_empty(self):
        for x in describe_host(name='sigjw8gu8a4fjrigljserg'):
            self.assertTrue(len(x) == 0)
            
            
if __name__ == "__main__":
    unittest.main()
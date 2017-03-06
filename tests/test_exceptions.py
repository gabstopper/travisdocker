"""
Test specific exceptions. This will catch SMCOperationFailure in GET request
and should return the proper SMCResult.
"""
import requests_mock
import unittest
from smc.tests.mocks import inject_mock_for_smc
from .constants import url
from smc.api.exceptions import SMCOperationFailure, ResourceNotFound
from smc.api.common import SMCRequest
from smc.base.util import find_type_from_self

def raise_smcopfail(request, context):
    raise SMCOperationFailure

class TestExceptions(unittest.TestCase):
    
    # Test exceptions from smc.api.common layer
    @classmethod
    def setUpClass(cls):
        """ 
        Set up SMC Session object once per test class. Primary reason is
        to load the Mock session object as smc.api.session._session since
        this assumes we will not have a real connection.
        """
        super(TestExceptions, cls).setUpClass()
        inject_mock_for_smc()
            
    @requests_mock.mock()
    def test_smcoperationfailure_nojson(self, m):
        # Invalid message (headers are json but no json body
        m.get('/foo', headers={'content-type': 'application/json'},
              status_code=400)
        result = SMCRequest(href='{}/foo'.format(url)).read()
        self.assertEqual(result.code, 400)
        self.assertTrue(result.msg.startswith('No valid message'))
    
    @requests_mock.mock()
    def test_smcoperationfailure_json(self, m):
        m.get('/foo', headers={'content-type': 'application/json'},
              json={'details': 'some error'}, status_code=400)
        result = SMCRequest(href='{}/foo'.format(url)).read()
        self.assertEqual(result.code, 400)
        self.assertTrue(result.msg.startswith('some error'))
    
    @requests_mock.mock()
    def test_smcoperationfailure_notjson(self, m):
        # With message
        m.get('/foo', [{'text': 'blah blah error', 'status_code': 400},
                       {'status_code': 400}])
        
        # With text output
        result = SMCRequest(href='{}/foo'.format(url)).read()
        self.assertEqual(result.code, 400)
        self.assertTrue(result.msg.startswith('blah blah'))
        
        # Only status code
        result = SMCRequest(href='{}/foo'.format(url)).read()
        self.assertEqual(result.code, 400)
        self.assertTrue(result.msg.startswith('No message returned'))
    
    @requests_mock.mock()    
    def test_smcoperationfailure_missing_msgparts(self, m):
        m.get('/foo', [{'json': {'message':'Impossible to store the element test.','status':'0'}, 
                        'status_code': 400, 'headers': {'content-type': 'application/json'}},
                       {'json': {'details':['Element name test is already used.'],'status':'0'},
                        'status_code': 400, 'headers': {'content-type': 'application/json'}}])
        
        # Missing detqils key
        result = SMCRequest(href='{}/foo'.format(url)).read()
        self.assertEqual(result.code, 400)
        self.assertTrue(result.msg.startswith('Impossible to store'))
        
        # Missing message key
        result = SMCRequest(href='{}/foo'.format(url)).read()
        self.assertEqual(result.code, 400)
        self.assertTrue(result.msg.startswith('Element name test'))
    
    @requests_mock.mock() 
    def test_validwith_messageanddetails(self, m):
        m.get('/foo', json={'message':'Impossible to store the element test.',
                            'details':['Element name test is already used.'],
                            'status':'0'}, 
                            status_code=400, headers={'content-type': 'application/json'})
        
        # Missing detqils key
        result = SMCRequest(href='{}/foo'.format(url)).read()
        self.assertEqual(result.code, 400)
        self.assertTrue(result.msg.startswith('Impossible to store the element test. Element name '
                                              'test is already used'))
    
    def test_resource_not_found(self):
        with self.assertRaises(ResourceNotFound):
            find_type_from_self([])  
              
if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testOperationFailure']
    unittest.main()
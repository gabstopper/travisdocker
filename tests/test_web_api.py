'''
Created on Jun 1, 2016

@author: davidlepage
'''
import sys
import unittest
import logging
import requests
import requests_mock
from smc.tests.mocks import inject_mock_for_smc
from smc import session
from .constants import url
from smc.api.session import Session
from smc.api.web import SMCAPIConnection, SMCResult
from smc.api.web import SMCConnectionError
from smc.api.common import SMCRequest

def raise_connection_error(request, context):
    raise requests.exceptions.RequestException

class WebApiTest(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        """ 
        Set up SMC Session object once per test class. Primary reason is
        to load the Mock session object as smc.api.session._session since
        this assumes we will not have a real connection.
        """
        super(WebApiTest, cls).setUpClass()
        inject_mock_for_smc()
    
    def testHttpGetNoSession(self):
        session = SMCAPIConnection(Session())
        self.assertRaises(SMCConnectionError, lambda: session.send_request(method='GET', request=None))
        
    def testHttpPostNoSession(self):
        session = SMCAPIConnection(Session())
        self.assertRaises(SMCConnectionError, lambda: session.send_request(method='POST', request=None))
    
    def testHttpPutNoSession(self):
        session = SMCAPIConnection(Session())
        self.assertRaises(SMCConnectionError, lambda: session.send_request(method='PUT', request=None))
    
    def testHttpDeleteNoSession(self):
        session = SMCAPIConnection(Session())
        self.assertRaises(SMCConnectionError, lambda: session.send_request(method='DELETE', request=None))
    
    def testGetEntryHrefNoSession(self):
        session = Session()
        self.assertRaises(SMCConnectionError, lambda: session.cache.get_entry_href('test'))
    
    def testInvalidMethod(self):
        result = session.connection.send_request(method='FOO', request=None)
        self.assertIsInstance(result, SMCResult)
        self.assertTrue(result.msg.startswith('Unsupported method'))
   
    @requests_mock.mock()
    def testTimeoutDuringSession(self, m):
        m.post('/foo', text=raise_connection_error)
        req = SMCRequest(href='{}/foo'.format(url), filename=None)
        self.assertRaises(SMCConnectionError, lambda: req.create())
        
    @requests_mock.mock()
    def testSMCResult_asjson_nodata(self, m):
        m.get('/foo', headers={'content-type': 'application/json'},
              status_code=200)
        result = SMCRequest(href='{}/foo'.format(url)).read()
        self.assertEqual(result.code, 200)
        self.assertTrue(len(result.json) == 0)
    
    @requests_mock.mock()
    def testSMCResult_asoctetstream(self, m):
        m.get('/foo', [{'headers': {'content-type': 'application/octet-stream'},
                        'status_code': 200, 'text': 'some text content'},
                       {'headers': {'content-type': 'application/octet-stream'},
                        'status_code': 200}])
                        
        result = SMCRequest(href='{}/foo'.format(url)).read() 
        self.assertEqual(result.code, 200)
        self.assertTrue(result.content.startswith('some text'))
           
        result = SMCRequest(href='{}/foo'.format(url)).read() 
        self.assertEqual(result.code, 200)
        self.assertIsNone(result.content)

    
    @requests_mock.mock()
    def testSMCResult_textnodata(self, m):
        m.get('/foo', headers={'content-type': 'text/plain'},
              status_code=200)
        result = SMCRequest(href='{}/foo'.format(url)).read()
        self.assertIsNone(result.content)
        
    def test_stream_logging(self):
        from smc import set_stream_logger
        set_stream_logger()
        logger = logging.getLogger('smc')
        self.assertEqual(logging.DEBUG, logger.getEffectiveLevel())
        
        set_stream_logger(level=logging.INFO)
        self.assertEqual(logging.INFO, logger.getEffectiveLevel())
           
if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    logging.getLogger("smc").setLevel(logging.INFO)

    cli_logger = logging.StreamHandler(sys.stdout)
    cli_logger.setLevel(logging.INFO)
    formatter = logging.Formatter('%(message)s')
    cli_logger.setFormatter(formatter)
    logging.getLogger("smc").addHandler(cli_logger)
    unittest.main()
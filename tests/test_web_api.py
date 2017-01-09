'''
Created on Jun 1, 2016

@author: davidlepage
'''
import sys
import unittest
import logging
from smc.api.session import Session
from smc.api.web import SMCAPIConnection, SMCResult
from smc.api.web import SMCConnectionError

class Test(unittest.TestCase):

    print("Running WebAPI Test..")
    def testName(self):
        pass

class RequestMock(object):
    def __init__(self, 
                 text='{"details":["Element name test is already used."],\
                 "message":"Impossible to store the element test.",\
                 "status":"0"}',
                 headers={'content-type': 'application/json'}):
        self.status_code = 200
        self.headers = headers
        self.text = text
    
    def __getattr__(self, value):
        pass

class WebApiTest(unittest.TestCase):
    
    """ Test WebApi calls without sessions, triggering SMCConnectionError """
    def testHttpGetNoSession(self):
        session = SMCAPIConnection(Session())
        self.assertRaises(SMCConnectionError, lambda: session.send_request(method='GET', request='http://1.1.1.1/api/6.0/elements'))
    
    def testHttpPostNoSession(self):
        session = SMCAPIConnection(Session())
        self.assertRaises(SMCConnectionError, lambda: session.send_request(method='POST', request='http://1.1.1.1/api/6.0/elements'))
    
    def testHttpPutNoSession(self):
        session = SMCAPIConnection(Session())
        self.assertRaises(SMCConnectionError, lambda: session.send_request(method='PUT', request='http://1.1.1.1/api/6.0/elements'))
    
    def testHttpDeleteNoSession(self):
        session = SMCAPIConnection(Session())
        self.assertRaises(SMCConnectionError, lambda: session.send_request(method='DELETE', request='http://172.18.1.150:8082/api/6.0/elements'))
    
    def testGetEntryHrefNoSession(self):
        session = Session()
        self.assertRaises(SMCConnectionError, lambda: session.cache.get_entry_href('test'))
    
    def test_SMCResult_as_json_no_body(self):
        #Received an empty json body response
        result = SMCResult(RequestMock(text='{}'))
        self.assertIsInstance(result.json, list)
        self.assertTrue(len(result.json) == 0)

    def test_SMCResult_as_application_octetstream(self):
        result = SMCResult(RequestMock(headers={'content-type': 'application/octet-stream'},
                                       text='test octetstream'))
        self.assertEqual(result.content, 'test octetstream')

    def test_stream_logging(self):
        from smc import set_stream_logger
        set_stream_logger()
        logger = logging.getLogger('smc')
        self.assertEqual(logging.DEBUG, logger.getEffectiveLevel())
        
        set_stream_logger(level=logging.INFO)
        self.assertEqual(logging.INFO, logger.getEffectiveLevel())
        
    def test_bad_method(self):
        from .constants import url, api_key
        from smc import session
        session.login(url=url, api_key=api_key)
        class Mock: pass
        self.assertTrue(session.connection.send_request('bogus', Mock()).msg.startswith('Unsupported method'))
    
'''                                                      
class CLIArgsTest(unittest.TestCase):
    def testAllArgCombos(self):
        """ test every command, target and menu items against CLI Parser """
        for command in get_cmd():
            command_str = []
            for entry in format_arguments(command):
                command_str.append(command)
                command_str.append(entry[0])
                for arg, action in entry[1]:
                    command_str.append('--'+arg)
                    if action and action.get('action') == 'store_true':
                        pass #if store_true is set, it's a boolean flag argument
                    else:
                        command_str.append('foo') 
                #print "command str: %s" % command_str
                #This should be a dict - further possibly verify the optional versus non-optional args
                self.assertIsInstance(CLIParser(command_str).document, dict)
                
                command_str = []
             
class SMCUtilsTest(unittest.TestCase):   
    def testInvalidCommand(self): 
        self.assertRegexpMatches(SMCBroker(['yy']).validate(), 'Invalid command')
    
    def testIncorrectSyntax(self):          
        self.assertRegexpMatches(SMCBroker(['create','host']).validate(), 'Incorrect')
'''              
           
if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    logging.getLogger("smc").setLevel(logging.INFO)

    cli_logger = logging.StreamHandler(sys.stdout)
    cli_logger.setLevel(logging.INFO)
    formatter = logging.Formatter('%(message)s')
    cli_logger.setFormatter(formatter)
    logging.getLogger("smc").addHandler(cli_logger)
    unittest.main()
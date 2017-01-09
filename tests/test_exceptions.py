'''
Created on Sep 30, 2016

@author: davidlepage
'''
import unittest
from .constants import url, api_key, verify
from smc.api.exceptions import SMCOperationFailure
from smc import session

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
    
class Test(unittest.TestCase):


    def setUp(self):
        print("-------Called setup-------")
        session.login(url=url, api_key=api_key, verify=verify)
    
    def tearDown(self):
        print("-------Called tear down-------")
        session.logout()
                   
    def test_OpFailure_with_no_message_and_json_headers(self):
        try:
            raise SMCOperationFailure(RequestMock(text='{}'))
        except SMCOperationFailure as e:
            result = e.smcresult
            self.assertEqual(result.code, 200)
            self.assertIsNone(result.content)
            self.assertIsNone(result.json)
            self.assertIsNone(result.href)
            self.assertIsNone(result.etag)
            self.assertIsNone(result.msg)
    
    def test_non_application_json_reply(self):
        #Reply as response.text
        try:
            raise SMCOperationFailure(RequestMock(headers={'content-type': 'text/plain'},
                                                  text='blah'))   
        except SMCOperationFailure as e:
            self.assertEqual(e.smcresult.msg, 'blah')
    
    def test_non_application_json_no_msg(self):
        #Reply wasnt json or text
        try:
            raise SMCOperationFailure(RequestMock(headers={'content-type': 'text/plain'},
                                                  text=None))
        except SMCOperationFailure as e:
            self.assertRegexpMatches(e.smcresult.msg, r'^HTTP error code')

    def test_repr(self):
        try:
            raise SMCOperationFailure(RequestMock())
        except SMCOperationFailure as e:
            self.assertIsNotNone(repr(e))

    def test_OpFailure_with_message(self):
        try:
            raise SMCOperationFailure(RequestMock())
        except SMCOperationFailure as e:
            self.assertTrue(e.smcresult.msg.startswith('Impossible to store'))
    
    def test_OpFailure_missing_details(self):
        try:
            raise SMCOperationFailure(RequestMock(text='{"message":"Impossible to store the element test.",\
                "status":"0"}'))
        except SMCOperationFailure as e:
            self.assertEqual(e.smcresult.msg, 'Impossible to store the element test.')
    
    def test_OpFailure_missing_message(self):
        try:
            raise SMCOperationFailure(RequestMock(text='{"details":["Element name test is already used."],\
                 "status":"0"}'))
        except SMCOperationFailure as e:
            self.assertEqual(e.smcresult.msg, 'Element name test is already used.')

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testOperationFailure']
    unittest.main()